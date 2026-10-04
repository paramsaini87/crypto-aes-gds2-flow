`timescale 1ns / 1ps
// ============================================================================
// AES-128 Encryption / Decryption Engine — FIPS 197 Compliant
// ============================================================================
// Iterative architecture: 10 rounds, 1 round/cycle (10-cycle latency).
// ECB mode block cipher. CTR/CBC handled in software.
// Full encrypt + decrypt in same datapath.
//
// Register Map (AXI4-Lite, 32-bit aligned):
//   0x00       CTRL          [0]=start(W1S,self-clr) [1]=mode 0=enc/1=dec
//                            [2]=key_valid(W1S) [3]=busy(RO) [4]=done(RO)
//   0x04       STATUS        [0]=done [1]=busy [7:4]=round_count(RO)
//   0x10-0x1C  KEY[0-3]      128-bit key   (4 x 32-bit)
//   0x20-0x2C  DATA_IN[0-3]  128-bit input (4 x 32-bit)
//   0x30-0x3C  DATA_OUT[0-3] 128-bit output (4 x 32-bit, RO)
//
// Copyright (c) 2024 IndepthSilicon. All rights reserved.
// ============================================================================

module crypto_aes (
    input         clk,
    input         rst_n,
    // AXI4-Lite slave
    input  [11:0] s_axi_awaddr,
    input         s_axi_awvalid,
    output        s_axi_awready,
    input  [31:0] s_axi_wdata,
    input  [3:0]  s_axi_wstrb,
    input         s_axi_wvalid,
    output        s_axi_wready,
    output [1:0]  s_axi_bresp,
    output        s_axi_bvalid,
    input         s_axi_bready,
    input  [11:0] s_axi_araddr,
    input         s_axi_arvalid,
    output        s_axi_arready,
    output [31:0] s_axi_rdata,
    output [1:0]  s_axi_rresp,
    output        s_axi_rvalid,
    input         s_axi_rready,
    // Interrupt
    output        irq
);

    // ================================================================
    // AES S-Box (SubBytes) — combinational, standard FIPS 197 table
    // ================================================================
    function [7:0] sbox;
        input [7:0] i;
        begin
            case (i)
                8'h00: sbox=8'h63; 8'h01: sbox=8'h7c; 8'h02: sbox=8'h77; 8'h03: sbox=8'h7b;
                8'h04: sbox=8'hf2; 8'h05: sbox=8'h6b; 8'h06: sbox=8'h6f; 8'h07: sbox=8'hc5;
                8'h08: sbox=8'h30; 8'h09: sbox=8'h01; 8'h0a: sbox=8'h67; 8'h0b: sbox=8'h2b;
                8'h0c: sbox=8'hfe; 8'h0d: sbox=8'hd7; 8'h0e: sbox=8'hab; 8'h0f: sbox=8'h76;
                8'h10: sbox=8'hca; 8'h11: sbox=8'h82; 8'h12: sbox=8'hc9; 8'h13: sbox=8'h7d;
                8'h14: sbox=8'hfa; 8'h15: sbox=8'h59; 8'h16: sbox=8'h47; 8'h17: sbox=8'hf0;
                8'h18: sbox=8'had; 8'h19: sbox=8'hd4; 8'h1a: sbox=8'ha2; 8'h1b: sbox=8'haf;
                8'h1c: sbox=8'h9c; 8'h1d: sbox=8'ha4; 8'h1e: sbox=8'h72; 8'h1f: sbox=8'hc0;
                8'h20: sbox=8'hb7; 8'h21: sbox=8'hfd; 8'h22: sbox=8'h93; 8'h23: sbox=8'h26;
                8'h24: sbox=8'h36; 8'h25: sbox=8'h3f; 8'h26: sbox=8'hf7; 8'h27: sbox=8'hcc;
                8'h28: sbox=8'h34; 8'h29: sbox=8'ha5; 8'h2a: sbox=8'he5; 8'h2b: sbox=8'hf1;
                8'h2c: sbox=8'h71; 8'h2d: sbox=8'hd8; 8'h2e: sbox=8'h31; 8'h2f: sbox=8'h15;
                8'h30: sbox=8'h04; 8'h31: sbox=8'hc7; 8'h32: sbox=8'h23; 8'h33: sbox=8'hc3;
                8'h34: sbox=8'h18; 8'h35: sbox=8'h96; 8'h36: sbox=8'h05; 8'h37: sbox=8'h9a;
                8'h38: sbox=8'h07; 8'h39: sbox=8'h12; 8'h3a: sbox=8'h80; 8'h3b: sbox=8'he2;
                8'h3c: sbox=8'heb; 8'h3d: sbox=8'h27; 8'h3e: sbox=8'hb2; 8'h3f: sbox=8'h75;
                8'h40: sbox=8'h09; 8'h41: sbox=8'h83; 8'h42: sbox=8'h2c; 8'h43: sbox=8'h1a;
                8'h44: sbox=8'h1b; 8'h45: sbox=8'h6e; 8'h46: sbox=8'h5a; 8'h47: sbox=8'ha0;
                8'h48: sbox=8'h52; 8'h49: sbox=8'h3b; 8'h4a: sbox=8'hd6; 8'h4b: sbox=8'hb3;
                8'h4c: sbox=8'h29; 8'h4d: sbox=8'he3; 8'h4e: sbox=8'h2f; 8'h4f: sbox=8'h84;
                8'h50: sbox=8'h53; 8'h51: sbox=8'hd1; 8'h52: sbox=8'h00; 8'h53: sbox=8'hed;
                8'h54: sbox=8'h20; 8'h55: sbox=8'hfc; 8'h56: sbox=8'hb1; 8'h57: sbox=8'h5b;
                8'h58: sbox=8'h6a; 8'h59: sbox=8'hcb; 8'h5a: sbox=8'hbe; 8'h5b: sbox=8'h39;
                8'h5c: sbox=8'h4a; 8'h5d: sbox=8'h4c; 8'h5e: sbox=8'h58; 8'h5f: sbox=8'hcf;
                8'h60: sbox=8'hd0; 8'h61: sbox=8'hef; 8'h62: sbox=8'haa; 8'h63: sbox=8'hfb;
                8'h64: sbox=8'h43; 8'h65: sbox=8'h4d; 8'h66: sbox=8'h33; 8'h67: sbox=8'h85;
                8'h68: sbox=8'h45; 8'h69: sbox=8'hf9; 8'h6a: sbox=8'h02; 8'h6b: sbox=8'h7f;
                8'h6c: sbox=8'h50; 8'h6d: sbox=8'h3c; 8'h6e: sbox=8'h9f; 8'h6f: sbox=8'ha8;
                8'h70: sbox=8'h51; 8'h71: sbox=8'ha3; 8'h72: sbox=8'h40; 8'h73: sbox=8'h8f;
                8'h74: sbox=8'h92; 8'h75: sbox=8'h9d; 8'h76: sbox=8'h38; 8'h77: sbox=8'hf5;
                8'h78: sbox=8'hbc; 8'h79: sbox=8'hb6; 8'h7a: sbox=8'hda; 8'h7b: sbox=8'h21;
                8'h7c: sbox=8'h10; 8'h7d: sbox=8'hff; 8'h7e: sbox=8'hf3; 8'h7f: sbox=8'hd2;
                8'h80: sbox=8'hcd; 8'h81: sbox=8'h0c; 8'h82: sbox=8'h13; 8'h83: sbox=8'hec;
                8'h84: sbox=8'h5f; 8'h85: sbox=8'h97; 8'h86: sbox=8'h44; 8'h87: sbox=8'h17;
                8'h88: sbox=8'hc4; 8'h89: sbox=8'ha7; 8'h8a: sbox=8'h7e; 8'h8b: sbox=8'h3d;
                8'h8c: sbox=8'h64; 8'h8d: sbox=8'h5d; 8'h8e: sbox=8'h19; 8'h8f: sbox=8'h73;
                8'h90: sbox=8'h60; 8'h91: sbox=8'h81; 8'h92: sbox=8'h4f; 8'h93: sbox=8'hdc;
                8'h94: sbox=8'h22; 8'h95: sbox=8'h2a; 8'h96: sbox=8'h90; 8'h97: sbox=8'h88;
                8'h98: sbox=8'h46; 8'h99: sbox=8'hee; 8'h9a: sbox=8'hb8; 8'h9b: sbox=8'h14;
                8'h9c: sbox=8'hde; 8'h9d: sbox=8'h5e; 8'h9e: sbox=8'h0b; 8'h9f: sbox=8'hdb;
                8'ha0: sbox=8'he0; 8'ha1: sbox=8'h32; 8'ha2: sbox=8'h3a; 8'ha3: sbox=8'h0a;
                8'ha4: sbox=8'h49; 8'ha5: sbox=8'h06; 8'ha6: sbox=8'h24; 8'ha7: sbox=8'h5c;
                8'ha8: sbox=8'hc2; 8'ha9: sbox=8'hd3; 8'haa: sbox=8'hac; 8'hab: sbox=8'h62;
                8'hac: sbox=8'h91; 8'had: sbox=8'h95; 8'hae: sbox=8'he4; 8'haf: sbox=8'h79;
                8'hb0: sbox=8'he7; 8'hb1: sbox=8'hc8; 8'hb2: sbox=8'h37; 8'hb3: sbox=8'h6d;
                8'hb4: sbox=8'h8d; 8'hb5: sbox=8'hd5; 8'hb6: sbox=8'h4e; 8'hb7: sbox=8'ha9;
                8'hb8: sbox=8'h6c; 8'hb9: sbox=8'h56; 8'hba: sbox=8'hf4; 8'hbb: sbox=8'hea;
                8'hbc: sbox=8'h65; 8'hbd: sbox=8'h7a; 8'hbe: sbox=8'hae; 8'hbf: sbox=8'h08;
                8'hc0: sbox=8'hba; 8'hc1: sbox=8'h78; 8'hc2: sbox=8'h25; 8'hc3: sbox=8'h2e;
                8'hc4: sbox=8'h1c; 8'hc5: sbox=8'ha6; 8'hc6: sbox=8'hb4; 8'hc7: sbox=8'hc6;
                8'hc8: sbox=8'he8; 8'hc9: sbox=8'hdd; 8'hca: sbox=8'h74; 8'hcb: sbox=8'h1f;
                8'hcc: sbox=8'h4b; 8'hcd: sbox=8'hbd; 8'hce: sbox=8'h8b; 8'hcf: sbox=8'h8a;
                8'hd0: sbox=8'h70; 8'hd1: sbox=8'h3e; 8'hd2: sbox=8'hb5; 8'hd3: sbox=8'h66;
                8'hd4: sbox=8'h48; 8'hd5: sbox=8'h03; 8'hd6: sbox=8'hf6; 8'hd7: sbox=8'h0e;
                8'hd8: sbox=8'h61; 8'hd9: sbox=8'h35; 8'hda: sbox=8'h57; 8'hdb: sbox=8'hb9;
                8'hdc: sbox=8'h86; 8'hdd: sbox=8'hc1; 8'hde: sbox=8'h1d; 8'hdf: sbox=8'h9e;
                8'he0: sbox=8'he1; 8'he1: sbox=8'hf8; 8'he2: sbox=8'h98; 8'he3: sbox=8'h11;
                8'he4: sbox=8'h69; 8'he5: sbox=8'hd9; 8'he6: sbox=8'h8e; 8'he7: sbox=8'h94;
                8'he8: sbox=8'h9b; 8'he9: sbox=8'h1e; 8'hea: sbox=8'h87; 8'heb: sbox=8'he9;
                8'hec: sbox=8'hce; 8'hed: sbox=8'h55; 8'hee: sbox=8'h28; 8'hef: sbox=8'hdf;
                8'hf0: sbox=8'h8c; 8'hf1: sbox=8'ha1; 8'hf2: sbox=8'h89; 8'hf3: sbox=8'h0d;
                8'hf4: sbox=8'hbf; 8'hf5: sbox=8'he6; 8'hf6: sbox=8'h42; 8'hf7: sbox=8'h68;
                8'hf8: sbox=8'h41; 8'hf9: sbox=8'h99; 8'hfa: sbox=8'h2d; 8'hfb: sbox=8'h0f;
                8'hfc: sbox=8'hb0; 8'hfd: sbox=8'h54; 8'hfe: sbox=8'hbb; 8'hff: sbox=8'h16;
                default: sbox = 8'h00;
            endcase
        end
    endfunction

    // ================================================================
    // AES Inverse S-Box (InvSubBytes)
    // ================================================================
    function [7:0] inv_sbox;
        input [7:0] i;
        begin
            case (i)
                8'h00: inv_sbox=8'h52; 8'h01: inv_sbox=8'h09; 8'h02: inv_sbox=8'h6a; 8'h03: inv_sbox=8'hd5;
                8'h04: inv_sbox=8'h30; 8'h05: inv_sbox=8'h36; 8'h06: inv_sbox=8'ha5; 8'h07: inv_sbox=8'h38;
                8'h08: inv_sbox=8'hbf; 8'h09: inv_sbox=8'h40; 8'h0a: inv_sbox=8'ha3; 8'h0b: inv_sbox=8'h9e;
                8'h0c: inv_sbox=8'h81; 8'h0d: inv_sbox=8'hf3; 8'h0e: inv_sbox=8'hd7; 8'h0f: inv_sbox=8'hfb;
                8'h10: inv_sbox=8'h7c; 8'h11: inv_sbox=8'he3; 8'h12: inv_sbox=8'h39; 8'h13: inv_sbox=8'h82;
                8'h14: inv_sbox=8'h9b; 8'h15: inv_sbox=8'h2f; 8'h16: inv_sbox=8'hff; 8'h17: inv_sbox=8'h87;
                8'h18: inv_sbox=8'h34; 8'h19: inv_sbox=8'h8e; 8'h1a: inv_sbox=8'h43; 8'h1b: inv_sbox=8'h44;
                8'h1c: inv_sbox=8'hc4; 8'h1d: inv_sbox=8'hde; 8'h1e: inv_sbox=8'he9; 8'h1f: inv_sbox=8'hcb;
                8'h20: inv_sbox=8'h54; 8'h21: inv_sbox=8'h7b; 8'h22: inv_sbox=8'h94; 8'h23: inv_sbox=8'h32;
                8'h24: inv_sbox=8'ha6; 8'h25: inv_sbox=8'hc2; 8'h26: inv_sbox=8'h23; 8'h27: inv_sbox=8'h3d;
                8'h28: inv_sbox=8'hee; 8'h29: inv_sbox=8'h4c; 8'h2a: inv_sbox=8'h95; 8'h2b: inv_sbox=8'h0b;
                8'h2c: inv_sbox=8'h42; 8'h2d: inv_sbox=8'hfa; 8'h2e: inv_sbox=8'hc3; 8'h2f: inv_sbox=8'h4e;
                8'h30: inv_sbox=8'h08; 8'h31: inv_sbox=8'h2e; 8'h32: inv_sbox=8'ha1; 8'h33: inv_sbox=8'h66;
                8'h34: inv_sbox=8'h28; 8'h35: inv_sbox=8'hd9; 8'h36: inv_sbox=8'h24; 8'h37: inv_sbox=8'hb2;
                8'h38: inv_sbox=8'h76; 8'h39: inv_sbox=8'h5b; 8'h3a: inv_sbox=8'ha2; 8'h3b: inv_sbox=8'h49;
                8'h3c: inv_sbox=8'h6d; 8'h3d: inv_sbox=8'h8b; 8'h3e: inv_sbox=8'hd1; 8'h3f: inv_sbox=8'h25;
                8'h40: inv_sbox=8'h72; 8'h41: inv_sbox=8'hf8; 8'h42: inv_sbox=8'hf6; 8'h43: inv_sbox=8'h64;
                8'h44: inv_sbox=8'h86; 8'h45: inv_sbox=8'h68; 8'h46: inv_sbox=8'h98; 8'h47: inv_sbox=8'h16;
                8'h48: inv_sbox=8'hd4; 8'h49: inv_sbox=8'ha4; 8'h4a: inv_sbox=8'h5c; 8'h4b: inv_sbox=8'hcc;
                8'h4c: inv_sbox=8'h5d; 8'h4d: inv_sbox=8'h65; 8'h4e: inv_sbox=8'hb6; 8'h4f: inv_sbox=8'h92;
                8'h50: inv_sbox=8'h6c; 8'h51: inv_sbox=8'h70; 8'h52: inv_sbox=8'h48; 8'h53: inv_sbox=8'h50;
                8'h54: inv_sbox=8'hfd; 8'h55: inv_sbox=8'hed; 8'h56: inv_sbox=8'hb9; 8'h57: inv_sbox=8'hda;
                8'h58: inv_sbox=8'h5e; 8'h59: inv_sbox=8'h15; 8'h5a: inv_sbox=8'h46; 8'h5b: inv_sbox=8'h57;
                8'h5c: inv_sbox=8'ha7; 8'h5d: inv_sbox=8'h8d; 8'h5e: inv_sbox=8'h9d; 8'h5f: inv_sbox=8'h84;
                8'h60: inv_sbox=8'h90; 8'h61: inv_sbox=8'hd8; 8'h62: inv_sbox=8'hab; 8'h63: inv_sbox=8'h00;
                8'h64: inv_sbox=8'h8c; 8'h65: inv_sbox=8'hbc; 8'h66: inv_sbox=8'hd3; 8'h67: inv_sbox=8'h0a;
                8'h68: inv_sbox=8'hf7; 8'h69: inv_sbox=8'he4; 8'h6a: inv_sbox=8'h58; 8'h6b: inv_sbox=8'h05;
                8'h6c: inv_sbox=8'hb8; 8'h6d: inv_sbox=8'hb3; 8'h6e: inv_sbox=8'h45; 8'h6f: inv_sbox=8'h06;
                8'h70: inv_sbox=8'hd0; 8'h71: inv_sbox=8'h2c; 8'h72: inv_sbox=8'h1e; 8'h73: inv_sbox=8'h8f;
                8'h74: inv_sbox=8'hca; 8'h75: inv_sbox=8'h3f; 8'h76: inv_sbox=8'h0f; 8'h77: inv_sbox=8'h02;
                8'h78: inv_sbox=8'hc1; 8'h79: inv_sbox=8'haf; 8'h7a: inv_sbox=8'hbd; 8'h7b: inv_sbox=8'h03;
                8'h7c: inv_sbox=8'h01; 8'h7d: inv_sbox=8'h13; 8'h7e: inv_sbox=8'h8a; 8'h7f: inv_sbox=8'h6b;
                8'h80: inv_sbox=8'h3a; 8'h81: inv_sbox=8'h91; 8'h82: inv_sbox=8'h11; 8'h83: inv_sbox=8'h41;
                8'h84: inv_sbox=8'h4f; 8'h85: inv_sbox=8'h67; 8'h86: inv_sbox=8'hdc; 8'h87: inv_sbox=8'hea;
                8'h88: inv_sbox=8'h97; 8'h89: inv_sbox=8'hf2; 8'h8a: inv_sbox=8'hcf; 8'h8b: inv_sbox=8'hce;
                8'h8c: inv_sbox=8'hf0; 8'h8d: inv_sbox=8'hb4; 8'h8e: inv_sbox=8'he6; 8'h8f: inv_sbox=8'h73;
                8'h90: inv_sbox=8'h96; 8'h91: inv_sbox=8'hac; 8'h92: inv_sbox=8'h74; 8'h93: inv_sbox=8'h22;
                8'h94: inv_sbox=8'he7; 8'h95: inv_sbox=8'had; 8'h96: inv_sbox=8'h35; 8'h97: inv_sbox=8'h85;
                8'h98: inv_sbox=8'he2; 8'h99: inv_sbox=8'hf9; 8'h9a: inv_sbox=8'h37; 8'h9b: inv_sbox=8'he8;
                8'h9c: inv_sbox=8'h1c; 8'h9d: inv_sbox=8'h75; 8'h9e: inv_sbox=8'hdf; 8'h9f: inv_sbox=8'h6e;
                8'ha0: inv_sbox=8'h47; 8'ha1: inv_sbox=8'hf1; 8'ha2: inv_sbox=8'h1a; 8'ha3: inv_sbox=8'h71;
                8'ha4: inv_sbox=8'h1d; 8'ha5: inv_sbox=8'h29; 8'ha6: inv_sbox=8'hc5; 8'ha7: inv_sbox=8'h89;
                8'ha8: inv_sbox=8'h6f; 8'ha9: inv_sbox=8'hb7; 8'haa: inv_sbox=8'h62; 8'hab: inv_sbox=8'h0e;
                8'hac: inv_sbox=8'haa; 8'had: inv_sbox=8'h18; 8'hae: inv_sbox=8'hbe; 8'haf: inv_sbox=8'h1b;
                8'hb0: inv_sbox=8'hfc; 8'hb1: inv_sbox=8'h56; 8'hb2: inv_sbox=8'h3e; 8'hb3: inv_sbox=8'h4b;
                8'hb4: inv_sbox=8'hc6; 8'hb5: inv_sbox=8'hd2; 8'hb6: inv_sbox=8'h79; 8'hb7: inv_sbox=8'h20;
                8'hb8: inv_sbox=8'h9a; 8'hb9: inv_sbox=8'hdb; 8'hba: inv_sbox=8'hc0; 8'hbb: inv_sbox=8'hfe;
                8'hbc: inv_sbox=8'h78; 8'hbd: inv_sbox=8'hcd; 8'hbe: inv_sbox=8'h5a; 8'hbf: inv_sbox=8'hf4;
                8'hc0: inv_sbox=8'h1f; 8'hc1: inv_sbox=8'hdd; 8'hc2: inv_sbox=8'ha8; 8'hc3: inv_sbox=8'h33;
                8'hc4: inv_sbox=8'h88; 8'hc5: inv_sbox=8'h07; 8'hc6: inv_sbox=8'hc7; 8'hc7: inv_sbox=8'h31;
                8'hc8: inv_sbox=8'hb1; 8'hc9: inv_sbox=8'h12; 8'hca: inv_sbox=8'h10; 8'hcb: inv_sbox=8'h59;
                8'hcc: inv_sbox=8'h27; 8'hcd: inv_sbox=8'h80; 8'hce: inv_sbox=8'hec; 8'hcf: inv_sbox=8'h5f;
                8'hd0: inv_sbox=8'h60; 8'hd1: inv_sbox=8'h51; 8'hd2: inv_sbox=8'h7f; 8'hd3: inv_sbox=8'ha9;
                8'hd4: inv_sbox=8'h19; 8'hd5: inv_sbox=8'hb5; 8'hd6: inv_sbox=8'h4a; 8'hd7: inv_sbox=8'h0d;
                8'hd8: inv_sbox=8'h2d; 8'hd9: inv_sbox=8'he5; 8'hda: inv_sbox=8'h7a; 8'hdb: inv_sbox=8'h9f;
                8'hdc: inv_sbox=8'h93; 8'hdd: inv_sbox=8'hc9; 8'hde: inv_sbox=8'h9c; 8'hdf: inv_sbox=8'hef;
                8'he0: inv_sbox=8'ha0; 8'he1: inv_sbox=8'he0; 8'he2: inv_sbox=8'h3b; 8'he3: inv_sbox=8'h4d;
                8'he4: inv_sbox=8'hae; 8'he5: inv_sbox=8'h2a; 8'he6: inv_sbox=8'hf5; 8'he7: inv_sbox=8'hb0;
                8'he8: inv_sbox=8'hc8; 8'he9: inv_sbox=8'heb; 8'hea: inv_sbox=8'hbb; 8'heb: inv_sbox=8'h3c;
                8'hec: inv_sbox=8'h83; 8'hed: inv_sbox=8'h53; 8'hee: inv_sbox=8'h99; 8'hef: inv_sbox=8'h61;
                8'hf0: inv_sbox=8'h17; 8'hf1: inv_sbox=8'h2b; 8'hf2: inv_sbox=8'h04; 8'hf3: inv_sbox=8'h7e;
                8'hf4: inv_sbox=8'hba; 8'hf5: inv_sbox=8'h77; 8'hf6: inv_sbox=8'hd6; 8'hf7: inv_sbox=8'h26;
                8'hf8: inv_sbox=8'he1; 8'hf9: inv_sbox=8'h69; 8'hfa: inv_sbox=8'h14; 8'hfb: inv_sbox=8'h63;
                8'hfc: inv_sbox=8'h55; 8'hfd: inv_sbox=8'h21; 8'hfe: inv_sbox=8'h0c; 8'hff: inv_sbox=8'h7d;
                default: inv_sbox = 8'h00;
            endcase
        end
    endfunction

    // ================================================================
    // GF(2^8) arithmetic for MixColumns / InvMixColumns
    // ================================================================
    function [7:0] xtime;
        input [7:0] a;
        begin
            xtime = {a[6:0], 1'b0} ^ (a[7] ? 8'h1b : 8'h00);
        end
    endfunction

    function [7:0] gf_mul2;
        input [7:0] a;
        begin gf_mul2 = xtime(a); end
    endfunction

    function [7:0] gf_mul3;
        input [7:0] a;
        begin gf_mul3 = xtime(a) ^ a; end
    endfunction

    function [7:0] gf_mul4;
        input [7:0] a;
        begin gf_mul4 = xtime(xtime(a)); end
    endfunction

    function [7:0] gf_mul8;
        input [7:0] a;
        begin gf_mul8 = xtime(xtime(xtime(a))); end
    endfunction

    // InvMixColumns multipliers: 0x09, 0x0b, 0x0d, 0x0e
    function [7:0] gf_mul9;
        input [7:0] a;
        begin gf_mul9 = gf_mul8(a) ^ a; end
    endfunction

    function [7:0] gf_mul11;
        input [7:0] a;
        begin gf_mul11 = gf_mul8(a) ^ gf_mul2(a) ^ a; end
    endfunction

    function [7:0] gf_mul13;
        input [7:0] a;
        begin gf_mul13 = gf_mul8(a) ^ gf_mul4(a) ^ a; end
    endfunction

    function [7:0] gf_mul14;
        input [7:0] a;
        begin gf_mul14 = gf_mul8(a) ^ gf_mul4(a) ^ gf_mul2(a); end
    endfunction

    // ================================================================
    // Rcon lookup
    // ================================================================
    function [7:0] rcon;
        input [3:0] r;
        begin
            case (r)
                4'd0: rcon = 8'h01;  4'd1: rcon = 8'h02;
                4'd2: rcon = 8'h04;  4'd3: rcon = 8'h08;
                4'd4: rcon = 8'h10;  4'd5: rcon = 8'h20;
                4'd6: rcon = 8'h40;  4'd7: rcon = 8'h80;
                4'd8: rcon = 8'h1b;  4'd9: rcon = 8'h36;
                default: rcon = 8'h00;
            endcase
        end
    endfunction

    // ================================================================
    // State machine
    // ================================================================
    localparam [2:0] ST_IDLE   = 3'd0,
                     ST_KEXP   = 3'd1,  // key expansion (10 cycles)
                     ST_INIT   = 3'd2,  // initial AddRoundKey
                     ST_ROUND  = 3'd3,  // rounds 1-9
                     ST_FINAL  = 3'd4,  // round 10 (no MixColumns)
                     ST_DONE   = 3'd5;

    reg [2:0]   fsm;
    reg [3:0]   round_cnt;
    reg         mode_dec;     // 0=encrypt, 1=decrypt
    reg         done_flag;
    reg         irq_r;
    assign irq = irq_r;

    // 128-bit state stored as 16 bytes: state[row][col]
    // Flattened as state[127:0] — byte 0 = state[127:120] = s[0][0]
    reg [127:0] st;

    // All 11 round keys (expanded once when key_valid written)
    reg [127:0] rk [0:10];

    // Software-facing registers
    reg [31:0]  key_reg [0:3];
    reg [31:0]  data_in [0:3];
    reg [31:0]  data_out [0:3];

    // Key expansion temporaries
    reg [3:0]   kexp_cnt;
    reg         key_expanding;

    // Start/key-expand requests raised by the AXI write channel and consumed by
    // the core FSM.  The AXI block owns these; the core block owns fsm,
    // mode_dec, done_flag, key_expanding, kexp_cnt, kw[] and rk[].  Every
    // register therefore has exactly one driver.
    reg         start_req;
    reg         start_mode;
    reg         kexp_req;

    // ================================================================
    // Byte helpers — extract / insert bytes from 128-bit word
    // State layout: st[127:120]=s00, st[119:112]=s10, st[111:104]=s20, st[103:96]=s30
    //               st[95:88] =s01, st[87:80]  =s11, st[79:72]  =s21, st[71:64] =s31
    //               st[63:56] =s02, st[55:48]  =s12, st[47:40]  =s22, st[39:32] =s32
    //               st[31:24] =s03, st[23:16]  =s13, st[15:8]   =s23, st[7:0]   =s33
    // Column-major: column j bytes at bits [(3-j)*32+31 : (3-j)*32]
    //   Within column: row 0 at top byte
    // ================================================================

    // Extract byte at (row, col)
    function [7:0] get_byte;
        input [127:0] s;
        input [1:0] row;
        input [1:0] col;
        reg [6:0] idx;
        begin
            idx = {(2'd3 - col), 2'b00, (2'd3 - row)} * 4'd8;
            // Simpler approach: compute bit position
            get_byte = s[((3-col)*32 + (3-row)*8) +: 8];
        end
    endfunction

    // ================================================================
    // SubBytes on full 128-bit state
    // ================================================================
    function [127:0] sub_bytes;
        input [127:0] s;
        integer sb;
        begin
            for (sb = 0; sb < 16; sb = sb + 1)
                sub_bytes[sb*8 +: 8] = sbox(s[sb*8 +: 8]);
        end
    endfunction

    function [127:0] inv_sub_bytes;
        input [127:0] s;
        integer sb;
        begin
            for (sb = 0; sb < 16; sb = sb + 1)
                inv_sub_bytes[sb*8 +: 8] = inv_sbox(s[sb*8 +: 8]);
        end
    endfunction

    // ================================================================
    // ShiftRows / InvShiftRows
    // State bytes in column-major order, 4 columns of 4 bytes.
    // Column j occupies st[(3-j)*32+31 : (3-j)*32], row 0 at MSB of column.
    // ShiftRows: row r is shifted left by r positions.
    // ================================================================
    function [127:0] shift_rows;
        input [127:0] s;
        reg [7:0] m [0:3][0:3]; // m[row][col]
        reg [7:0] o [0:3][0:3];
        integer sr, sc;
        begin
            // Unpack: column j at bits [(3-j)*32 +: 32], row 0 = MSByte
            for (sc = 0; sc < 4; sc = sc + 1)
                for (sr = 0; sr < 4; sr = sr + 1)
                    m[sr][sc] = s[((3-sc)*32 + (3-sr)*8) +: 8];
            // Shift row r left by r
            for (sr = 0; sr < 4; sr = sr + 1)
                for (sc = 0; sc < 4; sc = sc + 1)
                    o[sr][sc] = m[sr][(sc + sr) & 2'b11];
            // Repack
            shift_rows = 128'd0;
            for (sc = 0; sc < 4; sc = sc + 1)
                for (sr = 0; sr < 4; sr = sr + 1)
                    shift_rows[((3-sc)*32 + (3-sr)*8) +: 8] = o[sr][sc];
        end
    endfunction

    function [127:0] inv_shift_rows;
        input [127:0] s;
        reg [7:0] m [0:3][0:3];
        reg [7:0] o [0:3][0:3];
        integer sr, sc;
        begin
            for (sc = 0; sc < 4; sc = sc + 1)
                for (sr = 0; sr < 4; sr = sr + 1)
                    m[sr][sc] = s[((3-sc)*32 + (3-sr)*8) +: 8];
            // Shift row r right by r
            for (sr = 0; sr < 4; sr = sr + 1)
                for (sc = 0; sc < 4; sc = sc + 1)
                    o[sr][(sc + sr) & 2'b11] = m[sr][sc];
            inv_shift_rows = 128'd0;
            for (sc = 0; sc < 4; sc = sc + 1)
                for (sr = 0; sr < 4; sr = sr + 1)
                    inv_shift_rows[((3-sc)*32 + (3-sr)*8) +: 8] = o[sr][sc];
        end
    endfunction

    // ================================================================
    // MixColumns / InvMixColumns — operate on each column
    // ================================================================
    function [31:0] mix_column;
        input [31:0] col; // col[31:24]=row0, col[23:16]=row1, etc.
        reg [7:0] b0, b1, b2, b3;
        begin
            b0 = col[31:24]; b1 = col[23:16]; b2 = col[15:8]; b3 = col[7:0];
            mix_column[31:24] = gf_mul2(b0) ^ gf_mul3(b1) ^ b2         ^ b3;
            mix_column[23:16] = b0         ^ gf_mul2(b1) ^ gf_mul3(b2) ^ b3;
            mix_column[15:8]  = b0         ^ b1         ^ gf_mul2(b2) ^ gf_mul3(b3);
            mix_column[7:0]   = gf_mul3(b0) ^ b1         ^ b2         ^ gf_mul2(b3);
        end
    endfunction

    function [31:0] inv_mix_column;
        input [31:0] col;
        reg [7:0] b0, b1, b2, b3;
        begin
            b0 = col[31:24]; b1 = col[23:16]; b2 = col[15:8]; b3 = col[7:0];
            inv_mix_column[31:24] = gf_mul14(b0) ^ gf_mul11(b1) ^ gf_mul13(b2) ^ gf_mul9(b3);
            inv_mix_column[23:16] = gf_mul9(b0)  ^ gf_mul14(b1) ^ gf_mul11(b2) ^ gf_mul13(b3);
            inv_mix_column[15:8]  = gf_mul13(b0) ^ gf_mul9(b1)  ^ gf_mul14(b2) ^ gf_mul11(b3);
            inv_mix_column[7:0]   = gf_mul11(b0) ^ gf_mul13(b1) ^ gf_mul9(b2)  ^ gf_mul14(b3);
        end
    endfunction

    function [127:0] mix_columns;
        input [127:0] s;
        begin
            mix_columns = {mix_column(s[127:96]), mix_column(s[95:64]),
                           mix_column(s[63:32]),  mix_column(s[31:0])};
        end
    endfunction

    function [127:0] inv_mix_columns;
        input [127:0] s;
        begin
            inv_mix_columns = {inv_mix_column(s[127:96]), inv_mix_column(s[95:64]),
                               inv_mix_column(s[63:32]),  inv_mix_column(s[31:0])};
        end
    endfunction

    // ================================================================
    // Key Expansion — expand 128-bit key into 11 round keys
    // Performed when key_valid is written; stores into rk[0..10].
    // ================================================================
    reg [31:0] kw [0:3]; // current 4 key words for expansion

    // RotWord: rotate left by one byte
    function [31:0] rot_word;
        input [31:0] w;
        begin
            rot_word = {w[23:16], w[15:8], w[7:0], w[31:24]};
        end
    endfunction

    // SubWord: apply S-box to each byte
    function [31:0] sub_word;
        input [31:0] w;
        begin
            sub_word = {sbox(w[31:24]), sbox(w[23:16]),
                        sbox(w[15:8]),  sbox(w[7:0])};
        end
    endfunction

    // ================================================================
    // AES Core datapath
    // ================================================================
    integer ki;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            fsm        <= ST_IDLE;
            round_cnt  <= 4'd0;
            mode_dec   <= 1'b0;
            done_flag  <= 1'b0;
            irq_r      <= 1'b0;
            st         <= 128'd0;
            key_expanding <= 1'b0;
            kexp_cnt   <= 4'd0;
            for (ki = 0; ki < 4; ki = ki + 1) begin
                kw[ki]       <= 32'd0;
                data_out[ki] <= 32'd0;
            end
            for (ki = 0; ki <= 10; ki = ki + 1)
                rk[ki] <= 128'd0;
        end else begin
            irq_r <= 1'b0;

            // --- Key expansion FSM (runs independently) ---
            // Kickoff, moved here from the AXI block so key_expanding, kexp_cnt,
            // kw[] and rk[0] have a single driver.
            if (kexp_req && !key_expanding && fsm == ST_IDLE) begin
                kw[0] <= key_reg[0]; kw[1] <= key_reg[1];
                kw[2] <= key_reg[2]; kw[3] <= key_reg[3];
                rk[0] <= {key_reg[0], key_reg[1], key_reg[2], key_reg[3]};
                kexp_cnt      <= 4'd0;
                key_expanding <= 1'b1;
            end
            else if (key_expanding) begin
                begin : key_exp_block
                    reg [31:0] tmp;
                    tmp = kw[3];
                    tmp = rot_word(tmp);
                    tmp = sub_word(tmp);
                    tmp[31:24] = tmp[31:24] ^ rcon(kexp_cnt);
                    kw[0] <= kw[0] ^ tmp;
                    kw[1] <= kw[1] ^ (kw[0] ^ tmp);
                    kw[2] <= kw[2] ^ kw[1] ^ (kw[0] ^ tmp);
                    kw[3] <= kw[3] ^ kw[2] ^ kw[1] ^ (kw[0] ^ tmp);
                    rk[kexp_cnt + 1] <= {kw[0] ^ tmp,
                                          kw[1] ^ (kw[0] ^ tmp),
                                          kw[2] ^ kw[1] ^ (kw[0] ^ tmp),
                                          kw[3] ^ kw[2] ^ kw[1] ^ (kw[0] ^ tmp)};
                end
                if (kexp_cnt == 4'd9)
                    key_expanding <= 1'b0;
                kexp_cnt <= kexp_cnt + 4'd1;
            end

            // --- AES round FSM ---
            case (fsm)
                ST_IDLE: begin
                    // Start request from the AXI write channel.
                    if (start_req) begin
                        done_flag <= 1'b0;
                        mode_dec  <= start_mode;
                        fsm       <= ST_INIT;
                    end
                end

                ST_INIT: begin
                    // Initial AddRoundKey
                    if (mode_dec)
                        st <= {data_in[0], data_in[1], data_in[2], data_in[3]} ^ rk[10];
                    else
                        st <= {data_in[0], data_in[1], data_in[2], data_in[3]} ^ rk[0];
                    round_cnt <= 4'd1;
                    fsm       <= ST_ROUND;
                end

                ST_ROUND: begin
                    if (mode_dec) begin
                        // Decrypt: InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns
                        st <= inv_mix_columns(
                                inv_sub_bytes(inv_shift_rows(st)) ^ rk[10 - round_cnt]);
                    end else begin
                        // Encrypt: SubBytes → ShiftRows → MixColumns → AddRoundKey
                        st <= mix_columns(shift_rows(sub_bytes(st))) ^ rk[round_cnt];
                    end
                    if (round_cnt == 4'd9)
                        fsm <= ST_FINAL;
                    round_cnt <= round_cnt + 4'd1;
                end

                ST_FINAL: begin
                    if (mode_dec) begin
                        // Decrypt final: InvShiftRows → InvSubBytes → AddRoundKey
                        st <= inv_sub_bytes(inv_shift_rows(st)) ^ rk[0];
                    end else begin
                        // Encrypt final: SubBytes → ShiftRows → AddRoundKey (no MixColumns)
                        st <= shift_rows(sub_bytes(st)) ^ rk[10];
                    end
                    fsm <= ST_DONE;
                end

                ST_DONE: begin
                    data_out[0] <= st[127:96];
                    data_out[1] <= st[95:64];
                    data_out[2] <= st[63:32];
                    data_out[3] <= st[31:0];
                    done_flag   <= 1'b1;
                    irq_r       <= 1'b1;
                    fsm         <= ST_IDLE;
                end

                default: fsm <= ST_IDLE;
            endcase
        end
    end

    wire busy = (fsm != ST_IDLE) || key_expanding;

    // ================================================================
    // AXI4-Lite Write Channel
    // ================================================================
    reg        aw_ready_r, w_ready_r, b_valid_r;
    reg [11:0] aw_addr_r;
    reg        aw_done, w_done;
    reg [31:0] w_data_r;
    reg [3:0]  w_strb_r;

    assign s_axi_awready = aw_ready_r;
    assign s_axi_wready  = w_ready_r;
    assign s_axi_bresp   = 2'b00;
    assign s_axi_bvalid  = b_valid_r;

    function [31:0] byte_merge;
        input [31:0] old_val;
        input [31:0] new_val;
        input [3:0]  strb;
        begin
            byte_merge = {strb[3] ? new_val[31:24] : old_val[31:24],
                          strb[2] ? new_val[23:16] : old_val[23:16],
                          strb[1] ? new_val[15:8]  : old_val[15:8],
                          strb[0] ? new_val[7:0]   : old_val[7:0]};
        end
    endfunction

    integer ai;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            aw_ready_r <= 1'b0;  w_ready_r <= 1'b0;  b_valid_r <= 1'b0;
            aw_done <= 1'b0; w_done <= 1'b0;
            aw_addr_r <= 12'd0; w_data_r <= 32'd0; w_strb_r <= 4'd0;
            start_req <= 1'b0; start_mode <= 1'b0; kexp_req <= 1'b0;
            for (ai = 0; ai < 4; ai = ai + 1) begin
                key_reg[ai] <= 32'd0;
                data_in[ai] <= 32'd0;
            end
        end else begin
            aw_ready_r <= 1'b0;
            w_ready_r  <= 1'b0;
            // one-cycle pulses
            start_req  <= 1'b0;
            kexp_req   <= 1'b0;

            // Capture AW
            if (s_axi_awvalid && !aw_done && !b_valid_r) begin
                aw_ready_r <= 1'b1;
                aw_addr_r  <= s_axi_awaddr;
                aw_done    <= 1'b1;
            end

            // Capture W
            if (s_axi_wvalid && !w_done && !b_valid_r) begin
                w_ready_r <= 1'b1;
                w_data_r  <= s_axi_wdata;
                w_strb_r  <= s_axi_wstrb;
                w_done    <= 1'b1;
            end

            // Process write when both captured
            if (aw_done && w_done && !b_valid_r) begin
                b_valid_r <= 1'b1;
                case (aw_addr_r[7:0])
                    8'h00: begin // CTRL
                        if (w_strb_r[0]) begin
                            // Bit 0: start — request only; the core FSM owns fsm,
                            // mode_dec and done_flag and acts on this next cycle.
                            if (w_data_r[0] && !busy && !key_expanding) begin
                                start_req  <= 1'b1;
                                start_mode <= w_data_r[1];
                            end
                            // Bit 2: key_valid — request key expansion.  The core
                            // block owns kw[], rk[], kexp_cnt and key_expanding.
                            if (w_data_r[2] && !busy && !key_expanding) begin
                                kexp_req <= 1'b1;
                            end
                        end
                    end
                    // KEY[0-3]
                    8'h10: key_reg[0] <= byte_merge(key_reg[0], w_data_r, w_strb_r);
                    8'h14: key_reg[1] <= byte_merge(key_reg[1], w_data_r, w_strb_r);
                    8'h18: key_reg[2] <= byte_merge(key_reg[2], w_data_r, w_strb_r);
                    8'h1C: key_reg[3] <= byte_merge(key_reg[3], w_data_r, w_strb_r);
                    // DATA_IN[0-3]
                    8'h20: data_in[0] <= byte_merge(data_in[0], w_data_r, w_strb_r);
                    8'h24: data_in[1] <= byte_merge(data_in[1], w_data_r, w_strb_r);
                    8'h28: data_in[2] <= byte_merge(data_in[2], w_data_r, w_strb_r);
                    8'h2C: data_in[3] <= byte_merge(data_in[3], w_data_r, w_strb_r);
                    default: ;
                endcase
            end

            // Write response handshake
            if (b_valid_r && s_axi_bready) begin
                b_valid_r <= 1'b0;
                aw_done   <= 1'b0;
                w_done    <= 1'b0;
            end
        end
    end

    // ================================================================
    // AXI4-Lite Read Channel
    // ================================================================
    reg        ar_ready_r;
    reg [31:0] r_data_r;
    reg        r_valid_r;

    assign s_axi_arready = ar_ready_r;
    assign s_axi_rdata   = r_data_r;
    assign s_axi_rresp   = 2'b00;
    assign s_axi_rvalid  = r_valid_r;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            ar_ready_r <= 1'b0;
            r_data_r   <= 32'd0;
            r_valid_r  <= 1'b0;
        end else begin
            ar_ready_r <= 1'b0;

            if (s_axi_arvalid && !r_valid_r) begin
                ar_ready_r <= 1'b1;
                r_valid_r  <= 1'b1;
                case (s_axi_araddr[7:0])
                    8'h00: r_data_r <= {27'd0, done_flag, busy, 1'b0, mode_dec, 1'b0};
                    8'h04: r_data_r <= {24'd0, round_cnt, busy, done_flag};
                    8'h10: r_data_r <= key_reg[0];
                    8'h14: r_data_r <= key_reg[1];
                    8'h18: r_data_r <= key_reg[2];
                    8'h1C: r_data_r <= key_reg[3];
                    8'h20: r_data_r <= data_in[0];
                    8'h24: r_data_r <= data_in[1];
                    8'h28: r_data_r <= data_in[2];
                    8'h2C: r_data_r <= data_in[3];
                    8'h30: r_data_r <= data_out[0];
                    8'h34: r_data_r <= data_out[1];
                    8'h38: r_data_r <= data_out[2];
                    8'h3C: r_data_r <= data_out[3];
                    default: r_data_r <= 32'd0;
                endcase
            end

            if (r_valid_r && s_axi_rready)
                r_valid_r <= 1'b0;
        end
    end

endmodule
