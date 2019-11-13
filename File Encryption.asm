comment * -----------------------------------------------------
	-- Class:	CSC221 T/TH 5:30
	-- Created by:	Horacio Santoyo
	-- Created:	12/23/18
	-- Description:	Project 22
	-- Encrypt/Decrypt input file using passphrase, then write to output file
	--
	--------------------------------------------------------- *

INCLUDE Irvine32.inc 

.data
	PMAX = 64							; Passphrase buffer maximum size 
	BMAX = 5012							; Buffer maximum size 
	FNSIZE = BMAX
	RANGE=127
	PassPhrasePrompt BYTE 'Enter the passphrase: ',0 
	passLen BYTE 'Passphrase length: ',0
	PassPhraseIs BYTE 'Passphrase:	',0
	BufferIs BYTE 'Buffer:		',0
	CipherIs BYTE 'Cipher:		',0
	PSize DWORD PMAX
	BSize DWORD FNSIZE
	PassPhrase BYTE PMAX dup(0)					; Buffer for passphrase 
	Buffer BYTE BMAX dup(0)						; Buffer for (en/de-cryption) text
	Cipher BYTE BMAX dup(0)						; Buffer for cipher text
	Counter WORD 0							; Used for adding encrypted buffer to cipher

	infilename BYTE FNSIZE + 1 DUP(0)
	outfilename BYTE FNSIZE + 1 DUP(0)

	filenameSize DWORD ?
	fileHandle HANDLE 0
	promptEncDec BYTE 'Enter 0 to encrypt, 1 to decrypt: ',0
	EncDecType BYTE 0

.code
main proc

	; ==Get the passphrase from the user==
	mov esi, offset PassPhrasePrompt 
	mov edi, offset PassPhrase 
	mov ecx, PSize 
	call getString 
	mov PSize, eax 

	;==========Read File=========
	; Ask user for input file name
	mov ebx, OFFSET infilename					; Copy address into EBX for Inputfilename
	call Inputfilename

	; Open the file (try) and read intobuffer
	mov ebx, OFFSET inFileName
	mov esi, OFFSET buffer
	mov ecx, BMAX
	call OpenToRead
	call Read_File
	mov filenameSize, eax

	; Print passphrase lenght
	mov edx, offset passLen
	call WriteString
	mov eax, PSize
	call WriteDec
	call CrLf
	call CrLf

	; Ask user for process type
	mov edx, offset promptEncDec
	call WriteString
	mov edx, 0
	Call ReadDec
	mov EncDecType, al
	cmp eax, 0
	jz process
	call WriteDec
	mov edx, 0ffffffffh

	process:
	; ==========encrypt/decrypt buffer=========
	mov esi, offset buffer 
	mov edi, offset PassPhrase 
	mov ecx, BSize 
	mov ebx, PSize 
	call PrepCipher
	call CrLf 

	mov esi, offset PassPhraseIs
	mov edi, offset PassPhrase
	call displayStrings
	mov esi, offset BufferIs
	mov edi, offset Buffer
	call displayStrings
	mov esi, offset CipherIs
	mov edi, offset Cipher
	call displayStrings
	call CrLf

	;==========Write File=========
	; get the name of the file to write to (overwrite)
	mov ebx, OFFSET outfilename					; Copy address into EBX for ouputfilename
	call Inputfilename

	; open file for output
	mov esi, OFFSET cipher
	call OpenToWrite

	; writer buffer to output file 
	call WriteTo

	QUIT::
	exit

main endp

	;---------------------------------------------------- - 
	; getString that receives: 
	; esi - the address of a prompt (aks the user for something) 
	; edi - the address of the buffer where to put the string from the user 
	; ecx - the size of the buffer 
	; returns 
	; eax - number of char read 
	; have it restore the values of all register (except eax) 
	; ---------------------------------------------------- - 
	getString proc uses esi edi edx ecx 
		mov edx, esi 
		call WriteString 
		mov edx, edi 
		call readString 
		ret 
	getString endp 

	; ---------------------------------------------------- - 
	; displayStrings that recieves 
	; esi - the address of a prompt or description 
	; edi - the address the second string with some info 
	; returns: nothing 
	; it should printout the prompt, newline, 2nd string, and newline 
	; have it restore the values of all register (except eax) 
	; ---------------------------------------------------- - 
	displayStrings proc uses eax 
		mov edx, esi 
		call WriteString 
		mov edx, edi 
		mov eax, 0 
		mov al, "'"; 
		call writeChar 
		call WriteString 
		call writeChar 
		call CrLf 
		ret 
	displayStrings endp 

	; ---------------------------------------------------- -
	;
	; cipher call the en/de-crypt proc for each charater in
	; TEXT Buffer 
	;
	; loop through the characters in text buffer (esi) 
	; one at a time match it witha character from the 
	; passphrase buffer (edi) then call the cryp proc
	; 
	; the two buffers are not nessarrly the same size to 
	; it is very likey the second is much smaller 
	; so make sure the index of the second gets reset
	; 
	;
	; Receives: 
	;	 esi - address of the TEXT Buffer
	;	 edi - address of the Passpharse buffer
	;	 ecx - length of TEXT Buffer
	;	 ebx - length of Passphrase 
	;	 edx - =0encrypt / =0ffffffffhdecrypt 
	; Uses:	 
	;	 edx - index into PassPhrase
	;	 eax - chars 
	;	 - al - buffer
	;	 - ah - passphrase
	;	 - bits 31-16 set to 1 if decryption (encryption otherwise)
	; Returns: noting
	;		But changes buffer 
	; ---------------------------------------------------- -
	PrepCipher PROC
		pushad
		mov eax, 0						; zero chacters 
		mov eax, edx						; copy over upper 16 bits (crytion)
		mov ax,0						; zero out lower part of eax 
		mov edx, 0

		L1 :
			mov al, [esi]					; char from Buffer
			mov ah, [edi+edx]				; char from Passphrase

			call CipherChar					; transform char
			 
			push ebx
			mov ebx, 0
			mov bx, Counter
			mov cipher[ebx], al
			inc bx
			mov Counter, bx
			pop ebx

			inc esi						; increament point into BUFFER
			inc edx						; increament the INDEX in to passphrase
			cmp edx, ebx					; check if index greater then length of key string
			jb Skip
			mov edx, 0					; if edi > keySize reset it to zero 
			Skip:
			loop L1
		popad
		ret
	PrepCipher ENDP
		

	; ====================Encrypt/Decrypt start===================================

	; --------------------------------------------------
	; Does CipherChar 
	;
	;	AL had the char to transforms (call it VALUE) 
	;	AH has the char for the shift (the amount to shift) Call it SHIFT 
	;	LOWER = 32 (' ' or SPACE) and is the lowest printable ASCII char
	;	UPPER = 126 ('~') and is largest printable ASCII (7-bit ascii) 
	;
	;	if(VALUE < LOWER ) return- nothing to do if nonprintable
	;	if(VALUE >UPPER) return- nothing to do if DEL or extented ascii 
	;	VALUE = VALUE - LOWER (move into char (32-126) to be in range 0-94) 
	;	SHIFT = SHIFT - LOWER (move it into same range) 
	;	now both SHIF and VALUE will be between 0-94 (enstead of 32-126)
	;	VALUE = VALUE + SHIFT (if encrypting)
	;	VALUE = VALUE - SHIFT (if decrypting)
	;	VALUE = VALUE % UPPER - watch out for too bit or too small values)
	;			too bit modulo works fairly welltoo small and look negiative 
	;			7 bit acsii in 8 bits it a pain 
	;			next time I'll treat every thing as 16 bits 
	;	VALUE = VALUE + LOWER (add back so 0-94 bakc in 32-126 range)
	;
	; For Example
	;	 take a 7-bit ascii value (0-127)
	;	 if its between 31 and 127 (exclusively) it a printible char
	;	 subtract 32 (space) and the char value is in the range 0 to 94 (inclusively)
	;	 shift (add or sub) by a char from the passphrase (also with 32 subtracted) 
	;	 (modulo or subtract) to keep the shifted value in the 0-94 range	 
	;	 then adds back the 32 so back in orginal 7-bit ascii
	;
	; Receives: EAX
	;	 al - char to shift 
	;	 ah - amount to shift 
	;	 upper EAX used to store if we add or subtract (encrypt or decrypt) 
	;	 if not all zeros 0000SSVVh (SS shift char VV value char) - encryption
	;	 if upper not all zeros (0FFFFSSVVh) then- decryption
	;	 
	;				
	; Returns:transformed char in ax
	; --------------------------------------------------

	LOWER=32
	UPPER=94;
	LASTCHAR=126

	CipherChar PROC USES EBX ECX EDX ESI EDI
		mov ecx,0						; zero out - going to user for ShiftByChar
		mov edx,eax						; copy over shift and chars
		sar edx,16						; arthmetic shift (fill with signbit) and move 1s to lower part
		mov cl, ah						; copy over the ShiftBYChar
		mov ah,0						; zero out upper AX
		cmp al, LOWER						; space (ascii 32) is first printable
		jb DONE				 			; if control char dont do anything
		cmp al, LASTCHAR					; skip if above 126 
		ja DONE

		sub al, LOWER						; VALUE -= Lower_Bound :: range is now [0-94] 
		sub cl, LOWER						; SHIFT -= Lower_Bound	 (enstead of [32-126]) 
		 
		cmp edx, 0						; if anything in edx (>0) we are decrypting else encrypting
		jz AddingShift						; if decrypt is set to zero - we are encrypting
		jnz SubtractingShift
	AddingShift:
		 add al, cl						; VALUE += SHIFT(range: [(0-94) to (94-188)]

		cmp al, UPPER+UPPER					; 186(2*94) 
		jb DoMod1
		add al, UPPER						; byte is 0-255
 
		jmp ADD32
	DoMod1:
		mov ebx, UPPER						; set value for modulo - UPPER: keep in printable ascii 
		call Modulo						; do mod				
		jmp NEXT

	SubtractingShift:						; if decrypt is set to one we are decrypting
		sub al, cl						; VALUE -= SHIFT(range: [(-94)-0 to 0-94]
 
		cmp al, 163						; -93 looks the same as 163 in binary 
		jb DoMod
		add al, UPPER						; 93UPPER-1(0-93)=94; byte is 0-255ascii is 0-127
		jmp ADD32
	DoMod:
		mov ebx, UPPER						; set value for modulo - UPPER: keep in printable ascii 
		call Modulo						; do mod				
	NEXT:
		; ADD LOWER or SUB UPPER
		cmp al, UPPER
		jb ADD32
		sub al, UPPER
		jmp DONE
	ADD32:
		add al, LOWER						; VALUE += Lower_Bound

	DONE:
		ret
	CipherChar ENDP


	; --------------------------------------------------
	; Does modulo 
	; AX = AX mod BX
	;
	; Receives: AX BX 
	; Returns:AX
	; --------------------------------------------------
	Modulo PROC USES EBX ECX EDX
		mov dx, 0						; clear edx (for remander)	
		mov cx, bx						; going to divide EAX by UPPER 
									; (range of printible charaters)
		div cx							; Quotient goes into in EAX, Remander in EDX
		mov ax, dx			 			; copy ofer remander
		ret
	Modulo ENDP

	;====================Encrypt/Decrypt end===================================		


	;====================File handling start===================================		
	;------------------------------------------------------
	; get filename from user
	;
	; uses globlefilename, filenameSize FNSIZE;(
	; Receives: 
	;	EBX - as the address of the filenaem buffer
	; Returns:
	;	modifies filename and filenameSize
	; MODIFIES EBX
	;------------------------------------------------------	
	Inputfilename PROC USES EAX EDX ECX EBX 
	.data
		filenamePrompt BYTE "Enter the filename: ",0
	.code
		mov edx, OFFSET filenamePrompt				; display a prompt
		call WriteString
		mov ecx, FNSIZE						; maximum character count
		mov edx, ebx			 			; assuming EBX has OFFSET copy it into EDX for ReadString
		call ReadString						; input string
		mov filenameSize, eax					; save length
		call Crlf
		ret
	Inputfilename ENDP
		

	; ---------------------------------------------------- 
	; Open the file for input. 
	; Receives: 
	;	 EBX - address on buffer with filename
	; Returns:
	;	EAX - address fileHandle
	; MODIFIES: fileHandle, buffer
	;---------------------------------------------------- 
		OpenToRead PROC
		; USES ECX EDX
		.data
			nopen BYTE "Cannot open file",0dh,0ah,0
		.code
			mov edx, ebx					; assuming EBX has address of filename buffer 
			call OpenInputFile
			mov fileHandle,eax

			; Check for errors
			cmp eax,INVALID_HANDLE_VALUE			; error opening file?
			jne file_ok					; no: skip

			mov edx, OFFSET nopen				; error message
			call WriteString
			exit ; jmp QUIT					; "Game over, man" - jump to main's exit 
		file_ok:
			ret
	OpenToRead ENDP

	 
	; ---------------------------------------------------- 
	; Read from the Open the file.
	; Receives: 
	;	ESI - address of buffer with text fill with test
	;	EAX - addrees of fileHandle
	;	ECX - SIZE OF BUFFER
	; Returns:EAX - SIZE of Buffer
	; MODIFIES: fileHandle, buffer
	;---------------------------------------------------- 
	Read_File PROC USES EBX ECX EDX
		.data
			erread BYTE "Error reading file. ",0
			ersmall BYTE "Error: Buffer too small for the file",0dh,0ah,0
			fsize BYTE "File size: ",0
		.code
			; Read the file into a buffer.
			; mov ebx,ecx					; copy size 
			mov edx, esi					; esi should have address of our buffer 
			mov ecx,BMAX					; don't read too much 
			call ReadFromFile
			jnc check_size					; did we read anything? - ah the Carry Flag - cool
			mov edx, OFFSET erread				; error message
			call WriteString
			call close_file
			exit ; jmp quit					; "Game over, man" - jump to main's exit 

		check_size:						; we read in something
			; cmp eax, BMAX				 	; how much space do we have?
			cmp eax, ebx					; how much space do we have?
			jb buf_size_ok					; enough - okay
			mov edx, OFFSET ersmall		 		; too big for buffer 
			call WriteString				; error message
			exit;jmp quit					; "Game over man, game over" - jump to main's exit
		buf_size_ok:
			mov BSize, eax					; save length
			add eax, esi
			mov [eax],BYTE PTR 0				; insert null terminator

			mov eax, BSize
			mov edx, OFFSET fsize				; show homw much was read in
			call WriteString
			call WriteDec					; display file size
			call Crlf

			; close_file:
			mov eax,fileHandle
			call CloseFile

			mov eax, BSize
			ret
	Read_File ENDP


	; ---------------------------------------------------- 
	; Open the file for output. mov edx,OFFSET filename call OpenInputFile
	;
	; Receives: EBX - address on buffer with filename
	; Returns:
	;
	; MODIFIES: fileHandle, buffer
	;---------------------------------------------------- 	
	OpenToWrite PROC
		.data
			 ncreat BYTE "Cannot create file",0dh,0ah,0
		.code
			; Create a new text file.
			mov edx, ebx					; move in address of buffer 
			call CreateOutputFile				; create a new file (or overwrite)
			mov fileHandle,eax				; save handle
			
			; Check for errors.
			cmp eax, INVALID_HANDLE_VALUE 			; error found?
			jne file_ok					; no: skip
			mov edx,OFFSET ncreat				; display error
			call WriteString
			jmp quit					; if error jump to main's exit - exit stage left!
		file_ok:	
			ret
	OpenToWrite ENDP


	; ---------------------------------------------------- 
	; Open the file for output. mov edx,OFFSET filename call OpenInputFile
	;
	; Receives: EBX - address on buffer with filename
	;			ESI - address of buffer with text to write
	; Returns:
	;
	; MODIFIES: fileHandle, buffer
	;----------------------------------------------------		
	WriteTo PROC
		.data
			 brf BYTE "Bytes written: ",0
			 bytesWritten DWORD ?
		.code

		; Write the buffer to the output file. 
		mov eax,fileHandle
		mov edx, esi						; esi is address of buffer (to fill)
		mov ecx,BSize						; how much we can read in 
		call WriteToFile		
		mov bytesWritten,eax					; how we ACTUALLY read in 
		call CloseFile							

		; Display the return value. 
		mov edx,OFFSET brf
		call WriteString
		mov eax,bytesWritten 
		call WriteDec
		call Crlf	
		ret 

	WriteTo ENDP
		
	; ---------------------------------------------------- 
	; Closes the file assoiciated with fileHandle. 
	;
	; Receives: 
	; Returns:
	; MODIFIES: fileHandle
	;---------------------------------------------------- 		
	Close_File PROC
		mov eax,fileHandle 
		call CloseFile
		ret
	Close_File ENDP	

	; ====================File handling end===================================

END main
