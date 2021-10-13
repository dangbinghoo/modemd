/**
 * X-Y Modem file receiving support.
 *
 *  (c) 2021 dangbinghoo
 *
 * This is massivelly adapted from BareBox's C code. 
 *  originlly Copyright (C) 2008 Robert Jarzmik @ GPLv2+
 */
module modemd.xymodem;

import core.stdc.stdint;
import std.stdio;

/// Protol Magic Signs
private enum ProtolSigns {
    SOH = 0x01,
    STX = 0x02,
    EOT = 0x04,
    ACK = 0x06,
    BSP = 0x08,
    NAK = 0x15,
    CAN = 0x18
}

/// Modem protocols
private enum ModemProtol {
    XModem  = 0,
    YModem  = 1,
    YModemG = 2
}

/// Modem protocols
private enum CRCType {
    None  = 0,
    Add8  = 1,
    CRC16 = 2      /* CCCIT-16 */
}

private enum {
    MaxRetries = 10,       /// Max transimit retries.
    MaxRetriesCRC = 5,     /// Max transimit retries when using CRC.
    MaxCanBeforeAbourt = 5 /// Max wait before abort.
}

private enum {
    TimeoutRead = 1,
    TimeoutFlush = 1
}

private enum State {
    GetFileName,
    NegociateCRC,
    ReceiveBody,
    FinishedFile,
    FinishedXfer
}

private struct XYBlock {
    ubyte[1024] buf;
    uint len;
    uint seq;
}

/// Error code
enum RetCode {
    MD_ERR = -1,
    MD_OK = 0,
    MD_ERR_NULL_PTR = -2,
    MD_ERR_TIME_OUT = -3,
    MD_ERR_BAD_MSG = -4,
    MD_ERR_CONN_ABORTED = -5,
    MD_ERR_ALAR_READY = -6,
    MD_ERR_ILSEQ = -7,         /* Illegal byte sequence */
    MD_ERR_INVALID = -8,
}

/*
 * For XMODEM/YMODEM, always try to use the CRC16 versions, called also
 * XMODEM/CRC and YMODEM.
 * Only fallback to additive CRC (8 bits) if sender doesn't cope with CRC16.
 */

///
private immutable char[][] invitefileNameHDR = [
	[ 0, ProtolSigns.NAK, 'C' ],	            /* XMODEM */
	[ 0, ProtolSigns.NAK, 'C' ],	            /* YMODEM */
	[ 0, 'G', 'G' ],	                        /* YMODEM-G */
];
///
private immutable char[][] inviteFileBody= [
	[ 0, ProtolSigns.NAK, 'C' ],	            /* XMODEM */
	[ 0, ProtolSigns.NAK, 'C' ],	            /* YMODEM */
	[ 0, 'G', 'G' ],	                        /* YMODEM-G */
];
///
private immutable char[][] blockACK = [
	[ 0, ProtolSigns.ACK, ProtolSigns.ACK ],	/* XMODEM */
	[ 0, ProtolSigns.ACK, ProtolSigns.ACK ],	/* YMODEM */
	[ 0, 0, 0 ],		                        /* YMODEM-G */
];
///
private immutable char[][] blockNACK = [
	[ 0, ProtolSigns.NAK, ProtolSigns.NAK ],	/* XMODEM */
	[ 0, ProtolSigns.NAK, ProtolSigns.NAK ],	/* YMODEM */
	[ 0, 0, 0 ],		                        /* YMODEM-G */
];

/// external Call-backs
alias modemGetData = int function(in ubyte[] buff, size_t len, long timeout);
alias modemPutChar = void function(ubyte c);
alias modemFlush = void function();

private enum CRC16_INIT_CCCIT = 0x0;
private enum CRC16_MODBUS_INIT = 0xFFFF;

private uint16_t crc16_cccit(uint8_t *buff, size_t len)
{
    uint32_t i, j, c;
    uint32_t crc = CRC16_INIT_CCCIT;

    for(i = 0; i < len; i++) {
        c = *(buff + i) & 0xff;
        crc ^= c;
        for(j = 0; j < 8; j++) {
            if(crc & 0x0001) {
                crc >>= 1;

                crc ^= 0xa001;
            }else {
                crc >>= 1;
            }
        }
    }

    crc = (crc >> 8) + (crc << 8);
    return 0xffff & crc;
}

/// 
struct XYModem {
    private string filename;
    private ModemProtol proto;
    private CRCType crctype;
    private State state;

    private size_t filesize;
    private size_t recvcnt;
    private size_t nextblk;
    private size_t totalSOH, totalSTX, totalCAN, totalRetries;

    private modemGetData getdata;
    private modemPutChar putchar;
    private modemFlush flush;

    private File _file;

    /// register modem read data, put single char. and flash callbacks.
    int register(modemGetData getdata, modemPutChar putchar, modemFlush flush) {
        if ((getdata is null) || (putchar is null) || (flush is null)) {
            return RetCode.MD_ERR_NULL_PTR;
        }
        
        this.getdata = getdata;
        this.putchar = putchar;
        this.flush = flush;
        return RetCode.MD_OK;
    }

    private bool is_xmodem() {
        return this.proto == ModemProtol.XModem;
    }

    private void xy_block_ack() {
        const ubyte c = blockACK[this.proto][this.crctype];
        if (c)
            this.putchar(c);
    }

    private void xy_block_nack() {
        const ubyte c = blockACK[this.proto][this.crctype];
        if (c)
            this.putchar(c);
        this.totalRetries++;
    }

    private int check_crc(ubyte[] buf, size_t len, int crc_in, CRCType crc_type) {
        ubyte crc8 = 0;
        ushort crc16;
        
        switch (crc_type) {
            case CRCType.Add8:
                for (int i = 0; i < len; i++) {
                    crc8 += buf[i];
                }
                return crc8 == crc_in ? 0 : RetCode.MD_ERR_BAD_MSG;
            case CRCType.CRC16:
                crc16 = crc16_cccit(buf.ptr, len);
                return crc16 == crc_in ? 0 : RetCode.MD_ERR_BAD_MSG;
            case CRCType.None:
                return 0;
            default:
                return RetCode.MD_ERR_BAD_MSG;
        }
    }

    private int xy_read_block(ref XYBlock blk, uint64_t timeout) {
        int rc, data_len = 0;
        ubyte[1] hdr; ubyte[2] seqs, crcs;
        int crc = 0;
        bool hdr_found = 0;
        
        while (!hdr_found) {
            rc = this.getdata(hdr, 1, timeout);
            if (rc < 0)
                goto outerr;
            //timeout check

            switch (hdr[0]) {
                case ProtolSigns.SOH:
                    data_len = 128;
                    hdr_found = 1;
                    this.totalSOH++;
                    break;
                case ProtolSigns.STX:
                    data_len = 1024;
                    hdr_found = 1;
                    this.totalSTX++;
                    break;
                case ProtolSigns.CAN:
                    rc = RetCode.MD_ERR_CONN_ABORTED;
                    if (this.totalCAN++ > MaxCanBeforeAbourt)
                        goto outerr;
                    break;
                case ProtolSigns.EOT:
                    rc = 0;
                    blk.len = 0;
                    goto outerr;
                default:
                    break;
            }
        }

        blk.seq = 0;
        rc = this.getdata(seqs, 2, timeout);
        if (rc < 0)
            goto outerr;
        blk.seq = seqs[0];
        if (255 -seqs[0] != seqs[1])
            return RetCode.MD_ERR_BAD_MSG;

        rc = this.getdata(blk.buf, data_len, timeout);
        if (rc < 0)
            goto outerr;
        blk.len = rc;

        switch (this.crctype) {
            case CRCType.Add8:
                rc = this.getdata(crcs, 1, timeout);
                crc = crcs[0];
                break;
            case CRCType.CRC16:
                rc = this.getdata(crcs, 2, timeout);
                crc = (crcs[0] << 8) + crcs[1];
                break;
            case CRCType.None:
                rc = 0;
                break;
            default:
                rc = 0;
                break;
        }

        if (rc < 0)
            goto outerr;
        
        rc = check_crc(blk.buf, data_len, crc, this.crctype);
        if (rc < 0) {
            goto outerr;
        }

        return data_len;
    
    outerr:
        return rc;
    }

    private int xy_check_blk_seq(ref XYBlock blk, int read_rc) {
        if (blk.seq == ((this.nextblk -1) % 256))
            return RetCode.MD_ERR_ALAR_READY;
        
        if (blk.seq != this.nextblk)
            return RetCode.MD_ERR_ILSEQ;
        
        return read_rc;
    }

    private int parse_fisrt_block(ref XYBlock blk) {
        import std.conv : to;
        import std.array : split;

        size_t fileinfo_len;

        import core.stdc.string : strlen;
        fileinfo_len = strlen(cast(const char *)blk.buf.ptr);
        if (fileinfo_len > blk.len)
            return RetCode.MD_ERR_INVALID;
        
        string fileinfo = to!string(blk.buf);
        
        auto _divdstrs = fileinfo.split(" ");
        if (_divdstrs !is null && _divdstrs.length == 2) {
            this.filename = _divdstrs[0];
            this.filesize = to!int(_divdstrs[0]);
            return 0;
        }

        return RetCode.MD_ERR_INVALID;
    }

    private int xy_get_file_header() {
        XYBlock _blk;
        int tries, rc = 0;
        this.state = State.GetFileName;
        this.crctype = CRCType.CRC16;

        for (tries = 0; tries < MaxRetries; tries++) {
            this.putchar(invitefileNameHDR[this.proto][this.crctype]);
            rc =  xy_read_block(_blk, 3);
            switch (rc) {
                case RetCode.MD_ERR_CONN_ABORTED:
                    goto fail;
                case RetCode.MD_ERR_TIME_OUT:
                case RetCode.MD_ERR_BAD_MSG:
                    if (this.proto != ModemProtol.YModemG)
                        this.flush();
                    break;
                case RetCode.MD_ERR_ALAR_READY:
                default:
                    this.nextblk = 1;
                    xy_block_ack();
                    this.state = State.NegociateCRC;
                    rc = parse_fisrt_block(_blk);
                    return rc;
            }

            if ((rc < 0) && (tries++ >= MaxRetriesCRC)) {
                this.crctype = CRCType.Add8;
            }
        }
        rc = RetCode.MD_ERR_TIME_OUT;
    
    fail:
        this.totalRetries += tries;
        return rc;
    }

    private int xy_await_header() {
        int rc;

        rc = xy_get_file_header();
        if (rc < 0)
            return rc;
        
        this.state = State.NegociateCRC;

        if (this.filename.length > 0)
            this._file.open(this.filename, "w");
        else
            this.state = State.FinishedXfer;
        this.recvcnt = 0;
        return rc;
    }

    private void xy_finish_file() {
        this._file.close;
        this.state = State.FinishedFile;
    }

    private void xymodem_init(ModemProtol proto_type) {
        this.proto = proto_type;
        this.crctype = CRCType.CRC16;

        if (is_xmodem()) {
            this.state = State.NegociateCRC;
        }
        else {
            this.state = State.GetFileName;
        }
        this.flush();
    }

    private int xymodem_handle() {
        import std.algorithm : min;
        int rc = RetCode.MD_OK;
        int xfer_max, len = 0, again = 1;
        size_t remain;
        int crc_tries = 0, same_blk_retries = 0;
        ubyte invite;
        XYBlock blk;

        while (again) {
            switch (this.state) {
                case State.GetFileName:
                    crc_tries = 0;
                    rc = xy_await_header();
                    if (rc < 0)
                        goto fail;
                    continue;
                case State.FinishedFile:
                    if (is_xmodem())
                        this.state = State.FinishedXfer;
                    else
                        this.state = State.GetFileName;
                    this.putchar(ProtolSigns.ACK);
                    continue;
                case State.FinishedXfer:
                    again = 0; rc = 0;
                    goto outs;
                case State.NegociateCRC:
                    invite = inviteFileBody[this.proto][this.crctype];
                    this.nextblk = 1;
                    if (crc_tries++ > MaxRetriesCRC)
                        this.crctype = CRCType.Add8;
                    this.putchar(invite);
                    goto case; /* fallthrough */
                case State.ReceiveBody:
                    rc = xy_read_block(blk, 3);
                    if (rc > 0) {
                        rc = xy_check_blk_seq(blk, rc);
                    }
                    break;
                default:
                    break;
            }

            if (this.state != State.ReceiveBody)
                continue;
            
            switch (rc) {
                case RetCode.MD_ERR_CONN_ABORTED:
                    goto fail;
                case RetCode.MD_ERR_TIME_OUT:
                case RetCode.MD_ERR_BAD_MSG:
                case RetCode.MD_ERR_ILSEQ:
                    if (this.proto == ModemProtol.YModemG)
                        goto fail;
                    this.flush();
                    xy_block_nack();
                    break;
                case RetCode.MD_ERR_ALAR_READY:
                    xy_block_ack();
                    break;
                case 0:
                    xy_finish_file();
                    break;
                default:
                    remain = this.filesize - this.recvcnt;
                    if (is_xmodem())
                        xfer_max = blk.len;
                    else
                        xfer_max = min(blk.len, remain);
                    try {
                        this._file.write(blk.buf, xfer_max);
                        this.nextblk = ((blk.seq + 1) % 256);
                        this.recvcnt += xfer_max;
                        len += xfer_max;
                        xy_block_ack();
                    }
                    catch (Exception e) {

                    }

                    break;
            }

            if (rc < 0)
                same_blk_retries++;
            else
                same_blk_retries = 0;
            if (same_blk_retries > MaxRetries)
                goto fail;
        }

    outs:
    fail:
        this._file.close();
        return rc;
    }

    private void xymodem_close() {

    }

    /// X-Modem file transfer
    int doXmodemLoad() {
        int rc;
        xymodem_init(ModemProtol.XModem);
        do {
            rc = xymodem_handle();
        } while (rc > 0);
        xymodem_close();
        return rc;
    }

    /// Y-Modem file transfer
    int doYmodemLoad() {
        int rc;
        xymodem_init(ModemProtol.YModem);
        do {
            rc = xymodem_handle();
        } while (rc > 0);
        xymodem_close();
        return rc;
    }

    /// Y-Modem-G file transfer
    int doYmodemGLoad() {
        int rc;
        xymodem_init(ModemProtol.YModemG);
        do {
            rc = xymodem_handle();
        } while (rc > 0);
        xymodem_close();
        return rc;
    }
}
