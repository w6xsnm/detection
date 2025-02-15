import "pe"

rule revsocks {

    meta:
        author = "CDC"
        date = "14-02-2025"
        version = "1"
        description = "Detects revsocks"
		info = "https://github.com/kost/revsocks/tree/master"

    strings:
	
	// suspicious strings
	
	$p0 = "listen port for receiver address:port" fullword ascii
	$p1 = "certificate file" fullword ascii
	$p2 = "127.0.0.1:1080" fullword ascii
	$p3 = "socks address:port" fullword ascii
	$p4 = "connect address:port (or https://address:port for ws)" fullword ascii
	$p5 = "use proxy address:port for connecting (or http://address:port for ws)" fullword ascii
	$p6 = "Where should DNS server listen" fullword ascii
	$p7 = "Delay/sleep time between requests (200ms by default)" fullword ascii
	$p8 = "DNS domain to use for DNS tunneling" fullword ascii
	$p9 = "proxy response timeout (ms)" fullword ascii
	$p10 = "proxy auth Domain/user:Password" fullword ascii
	$p11 = "use domain.tld and automatically obtain TLS certificate" fullword ascii
	$p12 = "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko" fullword ascii
	$p13 = "Be quiet - do not display output" fullword ascii
	$p14 = "use websocket for connection" fullword ascii
	$p15 = "revsocks - reverse socks5 server/client by kost %s (%s)\n" fullword ascii
	$p16 = "Usage (standard tcp):" fullword ascii
	$p17 = "1) Start on the client: revsocks -listen :8080 -socks 127.0.0.1:1080 -pass test -tls" fullword ascii
	$p18 = "2) Start on the server: revsocks -connect client:8080 -pass test -tls" fullword ascii
	$p19 = "3) Connect to 127.0.0.1:1080 on the client with any socks5 client." fullword ascii
	$p20 = "Usage (dns):" fullword ascii
	$p21 = "1) Start on the DNS server: revsocks -dns example.com -dnslisten :53 -socks 127.0.0.1:1080" fullword ascii
	$p22 = "2) Start on the target: revsocks -dns example.com -pass <paste-generated-key>" fullword ascii
	$p23 = "3) Connect to 127.0.0.1:1080 on the DNS server with any socks5 client." fullword ascii
	
	// Tool reads only 64 bytes with timeout=1-3 sec
	
	$s0 = { 48 89 94 24 ?? ?? 00 00 [0-5] E8 ?? ?? ?? ?? (48 8B 3D ?? ?? ?? ?? | 48 BF 00 80 1E 08 6B 47 01) E8 ?? ?? ?? ?? 48 8B 94 24 ?? 00 00 00}
    
	/*
		48 89 94 24 70 01	| mov     [rsp+170h], rdx
		0F 1F 44 00 00		| <--- 0-5 bytes for nop
		E8 5B 7B C5 FF		| call    time_Now
		48 8B 3D E4 75 4A	| mov     rdi, cs:qword_D15A90 ; time_Duration
		E8 2F 73 C5 FF		| call    time_Time_Add
		48 8B 94 24 F8		| mov     rdx, [rsp+0F8h]
    */
	
	// Tool disables socket read timeouts
	
	$s1 = {48 8B 72 40 48 89 CF 48 89 D9 48 89 C3 48 8B 84 24 ?? ?? ?? ?? (FF D6 | 41 FF D0) 48 8D 05 ?? ?? ?? ?? (BB 40 00 00 00 | 48 8B 9C 24 ??)}

	/*
		48 8B 72 40       	| mov     rsi, [rdx+40h]
		48 89 CF          	| mov     rdi, rcx
		48 89 D9          	| mov     rcx, rbx
		48 89 C3          	| mov     rbx, rax
		48 8B 84 24 C8 01 	| mov     rax, [rsp+1C8h]
		FF D6             	| call    rsi
		48 8D 05 E9 9B 03 	| lea     rax, RTYPE_uint8
		BB 40 00 00 00    	| mov     ebx, 64 ;
	*/

	// main.connectForSocks call structure

	$s2 = {E8 ?? ?? ?? ?? 44 0F 11 BC 24 ?? [0-4] 48 85 C0 [0-6] ?? 8B 40 08}
	
	/*
		E8 59 18			| call    main_connectForSocks
		44 0F 11 BC 24 F8	| movups  xmmword ptr [rsp+0F8h], xmm15
		                    | <--- 0-4 bytes for nop
		48 85 C0            | test    rax, rax
		0F 84 1C FF FF FF	| jz      loc_7E9A35 	<--- 0-6 bytes for jump or short jump or long jump
		40 8B 40 08			| mov rax, [rax+8]      <--- probably reduce fp num
	*/
	
	// main.listenForClients call structure
	
	$s3 = {E8 ?? ?? ?? ?? 48 8B ?? 24 ?? BB E8 03 00 00 31 C9 31 FF}
	
	/* 
		E8 25 32 00 00		| call    main_listenForClients
		48 8B 44 24 78		| mov     rax, [rsp+1A8h+var_130] ; _ptr_websocket_Conn
		BB E8 03 00 00    	| mov     ebx, 3E8h       ; websocket_StatusCode
		31 C9             	| xor     ecx, ecx        ; string
		31 FF             	| xor     edi, edi
	*/ 	
    
	// main.getPEM call structure
    
	$s4 = {E8 ?? ?? ?? ?? 44 0F 11 BC 24 ?? 00 00 00 48 89 FA 48 8D BC 24 ?? 00 00 00 48 8D 7F ?? 48 89 6C 24 ?? 48 8D 6C 24 ??}
		
	/* 
		E8 2C FE FF FF		| call    main_getPEMs
		44 0F 11 BC 24 A8	| movups  [rsp+1A0h+var_F8], xmm15
		48 89 FA			| mov     rdx, rdi
		48 8D BC 24 B0		| lea     rdi, [rsp+1A0h+var_F8+8]
		48 8D 7F F0			| lea     rdi, [rdi-10h]
		48 89 6C 24 F0		| mov     [rsp+1A0h+var_1B0], rbp
		48 8D 6C 24 F0		| lea     rbp, [rsp+1A0h+var_1B0]
	*/
	
	// close websocket call structure
	
	$s5 = {E8 ?? ?? ?? ?? 0F B6 54 24 ?? F6 C2 02} 	
	
	/*
		E8 72 6B E9 FF    	| call    nhooyr_io_websocket__ptr_Conn_Close
		0F B6 54 24 46    	| movzx   edx, [rsp+1A8h+var_162]
		F6 C2 02          	| test    dl, 2
	*/
	
	condition:
        ( uint16 (0) == 0x5a4d or uint16 (0) == 0x457f ) and any of ($p*) and any of ($s*)
}