/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c

Written By: 
     1- Steve Dormady 
	 2- Shea Parcell
Submitted on: 
     Insert the date of Submission here
	 
----------------------------------------------------------------------------*/

#include "myCrypto.h"
#include "math.h"

//***********************************************************************
// pLAB-01
//***********************************************************************

void handleErrors( char *msg)
{
    fprintf( stderr , "\n%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    exit(-1);
}


//-----------------------------------------------------------------------------
// Encrypt the plaint text stored at 'pPlainText' into the 
// caller-allocated memory at 'pCipherText'
// Caller must allocate sufficient memory for the cipher text
// Returns size of the cipher text in bytes

// For the following Encryption/Decryption, 
// use a 256-bit key and AES in CBC mode (with a 128-bit IV)
// Ensure the (key,IV) being used match the specified algorithm

unsigned encrypt( uint8_t *pPlainText, unsigned plainText_len, 
             const uint8_t *key, const uint8_t *iv, uint8_t *pCipherText )
{

    int status;
    unsigned len = 0, encryptedLen = 0;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
        handleErrors("encrypt: failed to creat CTX");

    // Initialise the encryption operation.
    status = EVP_EncryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if(status != 1)
        handleErrors("encrypt: failed to EncryptInit_ex");

    // Call EncryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular encryption
    status = EVP_EncryptUpdate(ctx, pCipherText, &len, pPlainText, plainText_len);
    if(status != 1)
        handleErrors("encrypt: failed to EncryptUpdate");
    encryptedLen += len;

    // If additional ciphertext may still be generated,
    // the pCipherText pointer must be first advanced forward
    pCipherText += len;

    // Finalize the encryption.
    status = EVP_EncryptFinal_ex(ctx, pCipherText, &len);
    if(status != 1)
        handleErrors("encrypt: failed to EncryptFinal_ex");
    encryptedLen += len; // len could be 0 if no additional cipher text was generated

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return encryptedLen;

}

//-----------------------------------------------------------------------------
// Decrypt the cipher text stored at 'pCipherText' into the 
// caller-allocated memory at 'pDecryptedText'
// Caller must allocate sufficient memory for the decrypted text
// Returns size of the decrypted text in bytes

unsigned decrypt( uint8_t *pCipherText, unsigned cipherText_len, 
                  const uint8_t *key, const uint8_t *iv, uint8_t *pDecryptedText)
{

    int status;
    unsigned len = 0, decryptedLen = 0;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
        handleErrors("decrypt: failed to creat CTX");

    // Initialise the decryption operation.
    status = EVP_DecryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if(status != 1)
        handleErrors("decrypt: failed to DecryptInit_ex");

    // Call DecryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular decryption
    status = EVP_DecryptUpdate(ctx, pDecryptedText, &len, pCipherText, cipherText_len);
    if(status != 1)
        handleErrors("decrypt: failed to DecryptUpdate");
    decryptedLen += len;

    // If additional decrypted text may still be generated,
    // the pDecryptedText pointer must be first advanced forward
    pDecryptedText += len;

    // Finalize the decryption.
    status = EVP_DecryptFinal_ex(ctx, pDecryptedText, &len);
    if(status != 1)
        handleErrors("decrypt: failed to DecryptFinal_ex");
    decryptedLen += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return decryptedLen;

}

//***********************************************************************
// PA-01
//***********************************************************************

static unsigned char   plaintext [ PLAINTEXT_LEN_MAX ] , 
                       ciphertext[ CIPHER_LEN_MAX    ] ,
                       decryptext[ DECRYPTED_LEN_MAX ] ;

// above arrays being static to resolve runtime stack size issue. 
// However, that makes the code non-reentrant for multithreaded application
//-----------------------------------------------------------------------------

int encryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{

    int status = 0, bytes_read = 0;
    unsigned len = 0, encryptedLen = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        handleErrors("encrypt: failed to creat CTX");
    }
    // Initialise the encryption operation.
    status = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    if(status != 1) {
        handleErrors("encrypt: failed to EncryptInit_ex");
    }
    // int i = 0;
	while ((bytes_read = read(fd_in, plaintext, PLAINTEXT_LEN_MAX)) > 0)
        {
			status = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, bytes_read);
            if(status != 1)
            {
                handleErrors("encrypt: failed to EncryptUpdate");
            }
            ssize_t written_bytes = write(fd_out, ciphertext, len);   // <-- will block here
            if (written_bytes != len ){
                handleErrors("encrypt: failed to write out");
            }
            encryptedLen += len;
        }

    status = EVP_EncryptFinal_ex(ctx, ciphertext, &len);


    if(status != 1)
        handleErrors("encrypt: failed to EncryptFinal_ex");
    write(fd_out, ciphertext, len);
    encryptedLen += len; // len could be 0 if no additional cipher text was generated

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return encryptedLen;

}

//-----------------------------------------------------------------------------
int decryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{

    int status = 0, bytes_read = 0;
    unsigned len = 0, decryptedLen = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
        handleErrors("decrypt: failed to creat CTX");

    // Initialise the decryption operation.
    status = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    if(status != 1) {
        handleErrors("decrypt: failed to DecryptInit_ex");
    }

    while ( ( bytes_read = read(fd_in, ciphertext, CIPHER_LEN_MAX) ) > 0)
        {
            status = EVP_DecryptUpdate(ctx, decryptext, &len, ciphertext, bytes_read);
            if(status != 1)
                handleErrors("decrypt: failed to DecryptUpdate");
            int written_bytes = write(fd_out, decryptext, len);
            if (written_bytes != len )
                handleErrors("decrypt: failed to write out");
            decryptedLen += len;
        }
    // Finalize the encryption.

    len = 0;  
	status = EVP_DecryptFinal_ex(ctx, decryptext, &len);

    if(status != 1)
    {
        handleErrors("decrypt: failed to DecryptFinal_ex");
    }
    write(fd_out, decryptext, len);
    decryptedLen += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return decryptedLen;

}

//***********************************************************************
// pLAB-02
//***********************************************************************


EVP_PKEY *getRSAfromFile(char * filename, int public)
{
    FILE * fp = fopen(filename,"rb");
    if (fp == NULL)
    {
        fprintf( stderr , "getRSAfromFile: Unable to open RSA key file %s \n",filename);
        return NULL;    
    }

    EVP_PKEY *key = EVP_PKEY_new() ;
    if ( public )
        key = PEM_read_PUBKEY( fp, &key , NULL , NULL );
    else
        key = PEM_read_PrivateKey( fp , &key , NULL , NULL );
 
    fclose( fp );

    return key;
}

//***********************************************************************
// PA-02
//***********************************************************************
// Sign the 'inData' array into the 'sig' array using the private 'privKey'
// 'inLen' is the size of the input array in bytes.
// the '*sig' pointer will be allocated memory large enough to store the signature
// report the actual length in bytes of the result in 'sigLen' 
//
// Returns: 
//    1 on success, or 0 on ANY REASON OF FAILURE

int privKeySign( uint8_t **sig , size_t *sigLen , EVP_PKEY  *privKey , 
                 uint8_t *inData , size_t inLen ) 
{
    // Guard against incoming NULL pointers
    if ( !sig ||  !inData  ||  !privKey  )
    {
        printf(  "\n******* pkeySign received some NULL pointers\n" ); 
        return 0 ; 
    }

    // Create and Initialize a context for RSA private-key signing
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new( privKey , NULL /* NULL means use default RSA engine*/ );

    if ( ! ctx )
    {
        printf("Unable to creat a new context with Basim's public key\n" ); 
        exit( -1 ) ; 
    }

    if (EVP_PKEY_sign_init( ctx ) <= 0)
    {
        printf("Sign init failed");
        EVP_PKEY_CTX_free( ctx ); exit( -1 ) ;
    }

    if (  EVP_PKEY_CTX_set_rsa_padding( ctx, RSA_PKCS1_PADDING ) <= 0  )
    {
        printf("Unable to set the PADDING mode of the context for Basim's public key encryption\n" ); 
        EVP_PKEY_CTX_free( ctx ); exit( -1 ) ;
    }

    // Determine how big the size of the signature could be
    size_t cipherLen ;  //
    
    if (EVP_PKEY_sign( ctx, NULL, sigLen, inData, inLen) <= 0) // errors here
    {
        printf("Private key signing failed.\n");
        EVP_PKEY_CTX_free( ctx ); exit( -1 ) ;
    }

    // Next allocate memory for the ciphertext
    *sig = malloc (*sigLen);

    // Now, actually sign the inData using EVP_PKEY_sign( )
    if (EVP_PKEY_sign( ctx, *sig, sigLen, inData, inLen) <= 0) // errors here
    {
        printf("Private key signing failed.\n");
        EVP_PKEY_CTX_free( ctx ); exit( -1 ) ;
    }

    // All is good
    EVP_PKEY_CTX_free( ctx );     // remember to do this if any failure is encountered above

    return 1;
}

//-----------------------------------------------------------------------------
// Verify that the provided signature in 'sig' when decrypted using 'pubKey' 
// matches the data in 'data'
// Returns 1 if they match, 0 otherwise

int pubKeyVerify( uint8_t *sig , size_t sigLen , EVP_PKEY  *pubKey 
           , uint8_t *data , size_t dataLen ) 
{
    // Guard against incoming NULL pointers
    if ( !sig ||  !pubKey  ||  !data  )
    {
        printf(  "\n******* pkeySign received some NULL pointers\n" ); 
        return 0 ; 
    }

    // Create and Initialize a context for RSA public-key signature verification
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new( pubKey , NULL /* NULL means use default RSA engine*/ );

    if ( ! ctx )
    {
        printf("Unable to creat a new context with Basim's public key\n" ); 
        exit( -1 ) ; 
    }

    if ( EVP_PKEY_verify_init( ctx ) <= 0)
    {
        printf("Unable to initialize the context for Basim's public key encryption\n" ); 
        exit( -1 ) ;
    }

    if (  EVP_PKEY_CTX_set_rsa_padding( ctx, RSA_PKCS1_PADDING ) <= 0  )
    {
        printf("Unable to set the PADDING mode of the context for Basim's public key encryption\n" ); 
        exit( -1 ) ;
    }

    // Verify the signature vs the incoming data using this context
    int decision = EVP_PKEY_verify( ctx, sig, sigLen, data, dataLen ) ;
    if (decision < 0)
    {
        printf("Unable to verify public key.\n");
        EVP_PKEY_CTX_free( ctx ); exit( -1 ) ;
    }
    //  free any dynamically-allocated objects 
    EVP_PKEY_CTX_free( ctx );
    
    return decision ;

}

//-----------------------------------------------------------------------------


size_t fileDigest( int fd_in , int fd_out , uint8_t *digest )
// Read all the incoming data stream from the 'fd_in' file descriptor
// Apply the HASH_ALGORITHM() to compute the hash value of this incoming data into the array 'digest'
// If the file descriptor 'fd_out' is > 0, also write a copy of the incoming data stream file to 'fd_out'
// Returns actual size in bytes of the computed digest
{
    EVP_MD_CTX *mdCtx ;
    size_t nBytes ;
    unsigned int  mdLen ;

	// Use EVP_MD_CTX_create() to create new hashing context    
    // EVP_MD_CTX_new()
    mdCtx = EVP_MD_CTX_new();
    
    // Initialize the context using EVP_DigestInit() so that it deploys 
	// the HASH_ALGORITHM() hashing function 
    EVP_DigestInit(  mdCtx, HASH_ALGORITHM());

    ssize_t bytes_read = 0;
    while ( (bytes_read = read (fd_in, ciphertext, CIPHER_LEN_MAX)) > 0 )   // Loop until end-of input file
    {
        // Read a chunk of input from fd_in. Exit the loop when End-of-File is reached
        
        EVP_DigestUpdate( mdCtx, ciphertext, bytes_read);
        
        // if ( fd_out > 0 ) send the above chunk of data to fd_out
        if ( fd_out > 0)
        {
            write(fd_out, ciphertext, bytes_read);
        }
    }

    EVP_DigestFinal( mdCtx, digest, &mdLen);
    
    EVP_MD_CTX_free( mdCtx );

    return mdLen ;
}

//***********************************************************************
// PA-04  Part  One
//***********************************************************************

void exitError( char *errText )
{
    fprintf( stderr , "%s\n" , errText ) ;
    exit(-1) ;
}

//-----------------------------------------------------------------------------
// Utility to read Key/IV from a file
// Return:  1 on success, or 0 on failure

int getKeyFromFile( char *keyF , myKey_t *x )
{
    int   fd_key  ;
    
    fd_key = open( keyF , O_RDONLY )  ;
    if( fd_key == -1 ) 
    { 
        fprintf( stderr , "\nCould not open key file '%s'\n" , keyF ); 
        return 0 ; 
    }

    // first, read the symmetric encryption key
	if( SYMMETRIC_KEY_LEN  != read ( fd_key , x->key , SYMMETRIC_KEY_LEN ) ) 
    { 
        fprintf( stderr , "\nCould not read key from file '%s'\n" , keyF ); 
        return 0 ; 
    }

    // Next, read the Initialialzation Vector
    if ( INITVECTOR_LEN  != read ( fd_key , x->iv , INITVECTOR_LEN ) ) 
    { 
        fprintf( stderr , "\nCould not read the IV from file '%s'\n" , keyF ); 
        return 0 ; 
    }
	
    close( fd_key ) ;
    
    return 1;  //  success
}

//-----------------------------------------------------------------------------
// Allocate & Build a new Message #1 from Amal to the KDC 
// Where Msg1 is:  Len(A)  ||  A  ||  Len(B)  ||  B  ||  Na
// All Len(*) fields are size_t integers
// Set *msg1 to point at the newly built message
// Msg1 is not encrypted
// Returns the size (in bytes) of Message #1 

size_t MSG1_new ( FILE *log , uint8_t **msg1 , const char *IDa , const char *IDb , const Nonce_t Na )
{

    //  Check agains any NULL pointers in the arguments
    if (log == NULL || msg1 == NULL || IDa == NULL || IDb == NULL || Na == NULL)
    {
        return -1;
    }
                    // strlen is returning 12 when it should be 13...
    size_t  LenA    = strlen(IDa) + 1;//  number of bytes in IDa ;
    size_t  LenB    = strlen(IDb) + 1;//  number of bytes in IDb ;
    size_t  LenMsg1 = LENSIZE + LenA + LENSIZE + LenB + NONCELEN; // Wrong? //  number of bytes in the completed MSG1 ;;
    size_t *lenPtr = NULL; // ? 
    uint8_t  *p ;
    // sizeof(IDa) + LenA + sizeof(IDb) + LenB + sizeof(Na)

    // Allocate memory for msg1. MUST always check malloc() did not fail
    *msg1 = (uint8_t *) malloc(LenMsg1);
    if (! msg1)
    {
        return 0;
    }

    // Fill in Msg1:  Len( IDa )  ||  IDa   ||  Len( IDb )  ||  IDb   ||  Na
    p = *msg1;
    memcpy(p, &LenA, LENSIZE);
    // fprintf(log, "A: %lu\n", LenA);
    // fprintf(log, "A: %lu\n", LENSIZE);
    p += LENSIZE;
    memcpy(p, IDa,  LenA);               
    p += LenA;

    memcpy(p, &LenB, LENSIZE);
    // fprintf(log, "B: %lu\n", LenB);  
    p += LENSIZE;
    memcpy(p, IDb,  LenB);               
    p += LenB;

    memcpy(p, Na, NONCELEN);
    p += NONCELEN;
	// use the pointer p to traverse through msg1 and fill the successive parts of the msg 

    fprintf( log , "The following new MSG1 ( %lu bytes ) has been created by MSG1_new ():\n" , LenMsg1 ) ;
    // BIO_dumpt the completed MSG1 indented 4 spaces to the right
    BIO_dump_indent_fp(log, *msg1, LenMsg1, 4);
    fprintf( log , "\n" ) ;
    
    return LenMsg1 ;
}

//-----------------------------------------------------------------------------
// Receive Message #1 by the KDC from Amal via the pipe's file descriptor 'fd'
// Parse the incoming msg1 into the values IDa, IDb, and Na

void  MSG1_receive( FILE *log , int fd , char **IDa , char **IDb , Nonce_t Na )
{

    //  Check agains any NULL pointers in the arguments
    if (log == NULL || IDa == NULL || IDb == NULL || Na == NULL)
    {
        return;
    }

    size_t LenMsg1 = 0, LenA , lenB ;
	// Throughout this function, don't forget to update LenMsg1 as you receive its components
 
    // Read in the components of Msg1:  Len(IDa)  ||  IDa  ||  Len(IDb)  ||  IDb  ||  Na

    // 1) Read Len(ID_A)  from the pipe ... But on failure to read Len(IDa): 
    if (read(fd, &LenA, LENSIZE) != LENSIZE)
    {
        fprintf( log , "Unable to receive all %lu bytes of Len(IDA) "
                       "in MSG1_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes LenA in MSG1_receive()" );
    }
    LenMsg1 += LENSIZE;
    
    // 2) Allocate memory for ID_A ... But on failure to allocate memory:
    *IDa = calloc(LenA + 1, 1);
    if (*IDa == NULL)
    {
        fprintf( log , "Out of Memory allocating %lu bytes for IDA in MSG1_receive() "
                       "... EXITING\n" , LenA );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDA in MSG1_receive()" );
    }

 	// On failure to read ID_A from the pipe
    if (read(fd, *IDa, LenA) != (ssize_t)LenA)
    {
        fprintf( log , "Out of Memory allocating %lu bytes for IDA in MSG1_receive() "
                       "... EXITING\n" , LenA );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDA in MSG1_receive()" );
    }
    LenMsg1 += LenA;

    // 3) Read Len( ID_B )  from the pipe    But on failure to read Len( ID_B ):
    if (read(fd, &lenB, LENSIZE) != LENSIZE)
    {
        fprintf( log , "Unable to receive all %lu bytes of Len(IDB) "
                       "in MSG1_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of LenB in MSG1_receive()" );
    }
    LenMsg1 += LENSIZE;

    // 4) Allocate memory for ID_B    But on failure to allocate memory:
    *IDb = calloc(lenB + 1, 1);
    if (*IDb == NULL)
    {
        fprintf( log , "Out of Memory allocating %lu bytes for IDB in MSG1_receive() "
                       "... EXITING\n" , lenB );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDB in MSG1_receive()" );
    }

 	// Now, read IDb ... But on failure to read ID_B from the pipe
    if (read(fd, *IDb, lenB) != (ssize_t)lenB)
    {
        fprintf( log , "Unable to receive all %lu bytes of IDB in MSG1_receive() "
                       "... EXITING\n" , lenB );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Unable to receive all bytes of IDB in MSG1_receive()" );
    }
    LenMsg1 += lenB;
    
    // 5) Read Na   But on failure to read Na from the pipe
    if (read(fd, Na, NONCELEN) != NONCELEN)
    {
        fprintf( log , "Unable to receive all %lu bytes of Na "
                       "in MSG1_receive() ... EXITING\n" , NONCELEN );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of Na in MSG1_receive()" );
    }
    LenMsg1 += NONCELEN;
 
    fprintf( log , "MSG1 ( %lu bytes ) has been received"
                   " on FD %d by MSG1_receive():\n" ,  LenMsg1 , fd  ) ;   
    fflush( log ) ;

    return ;
}

//***********************************************************************
// PA-04   Part  TWO
//***********************************************************************
/*  Use these static arrays from PA-01 earlier

static unsigned char   plaintext [ PLAINTEXT_LEN_MAX ] , // Temporarily store plaintext
                       ciphertext[ CIPHER_LEN_MAX    ] , // Temporarily store outcome of encryption
                       decryptext[ DECRYPTED_LEN_MAX ] ; // Temporarily store decrypted text

// above arrays being static to resolve runtime stack size issue. 
// However, that makes the code non-reentrant for multithreaded application

*/

// Also, use this new one for your convenience
static unsigned char   ciphertext2[ CIPHER_LEN_MAX    ] ; // Temporarily store outcome of encryption

//-----------------------------------------------------------------------------
// Build a new Message #2 from the KDC to Amal
// Where Msg2 before encryption:  Ks || L(IDb) || IDb  || Na || L(TktCipher) || TktCipher
// All L() fields are size_t integers
// Set *msg2 to point at the newly built message
// Log milestone steps to the 'log' file for debugging purposes
// Returns the size (in bytes) of the encrypted (using Ka) Message #2  

size_t MSG2_new( FILE *log , uint8_t **msg2, const myKey_t *Ka , const myKey_t *Kb , 
                   const myKey_t *Ks , const char *IDa , const char *IDb  , Nonce_t *Na )
{

    size_t LenMsg2  = 0;
    int space = 0;

    //---------------------------------------------------------------------------------------
    // Construct TktPlain = { Ks  || L(IDa)  || IDa }
    // in the global scratch buffer plaintext[]
    size_t LenA    = strlen(IDa) + 1; 
    size_t LenTktPlain = KEYSIZE + LENSIZE + LenA; // This is good

    // int *TktPlain = calloc(1,LenTktPlain);
    // pointer arithmetic to build the ticket
    memcpy(plaintext + space, Ks, KEYSIZE);
    space += KEYSIZE;
    memcpy(plaintext + space, &LenA, LENSIZE);
    space += LENSIZE;
    memcpy(plaintext + space, IDa, LenA);
    space += LenA;

    // not used, but maybe we should?
    // char *ticketCipher = calloc (1, LenTktPlain);

    // encrypting the ticket
    LenMsg2 += LenTktPlain;
    size_t ticketLen = encrypt(plaintext, LenTktPlain, Kb->key, Kb->iv, ciphertext); //encrypt the ticket


    // Use that global array as a scratch buffer for building the plaintext of the ticket
    // Compute its encrypted version in the global scratch buffer ciphertext[]

    // Now, set TktCipher = encrypt( Kb , plaintext );
    // Store the result in the global scratch buffer ciphertext[]


    //---------------------------------------------------------------------------------------
    // Construct the rest of Message 2 then encrypt it using Ka
    // MSG2 plain = {  Ks || L(IDb) || IDb  ||  Na || L(TktCipher) || TktCipher }
    
    char *tempPlaintext = calloc(1, LenTktPlain); // this is to print the correct plaintext ticket.
    memcpy(tempPlaintext, plaintext, LenTktPlain);

    // Fill in Msg2 Plaintext:  Ks || L(IDb) || IDb  || L(Na) || Na || lenTktCipher) || TktCipher
    // Reuse that global array plaintext[] as a scratch buffer for building the plaintext of the MSG2
    size_t LenB    = strlen(IDb) + 1; 
    size_t LenMsgPlain = KEYSIZE + LENSIZE + LenB + NONCELEN + LENSIZE + ticketLen; // length of unencrypted message

    // pointer arichmetic to build the message
    space = 0;
    memcpy(plaintext + space, Ks, KEYSIZE);
    space += KEYSIZE;
    memcpy(plaintext + space, &LenB, LENSIZE);
    space += LENSIZE;
    memcpy(plaintext + space, IDb, LenB);
    space += LenB;
    memcpy(plaintext + space, Na, NONCELEN);
    space += NONCELEN;
    memcpy(plaintext + space, &ticketLen, LENSIZE);
    space += LENSIZE;
    memcpy(plaintext + space, ciphertext, ticketLen);
    space += ticketLen;

    // Now, encrypt Message 2 using Ka. 
    // Use the global scratch buffer ciphertext2[] to collect the results
    size_t final = encrypt(plaintext, LenMsgPlain, Ka->key, Ka->iv, ciphertext2);
    // errors here
    LenMsg2 = final;

    // allocate memory on behalf of the caller for a copy of MSG2 ciphertext
    *msg2 = calloc(1, LenMsg2 + LENSIZE);

    // Copy the encrypted ciphertext to Caller's msg2 buffer.
    memcpy (*msg2, ciphertext2, LenMsg2); // copy the encrypted message into the msg2 buffer

    // outputting the necessary data to KDC log
    fprintf( log , "Plaintext Ticket (%lu Bytes) is\n" ,  LenTktPlain  ) ;
    BIO_dump_indent_fp( log , tempPlaintext ,  LenTktPlain  , 4 ) ;    fprintf( log , "\n" ) ;
    fflush(log);
    fprintf( log , "The following Encrypted MSG2 ( %lu bytes ) has been"
                   " created by MSG2_new():  \n" ,  LenMsg2  ) ;
    BIO_dump_indent_fp( log , ciphertext2 ,  LenMsg2  , 4 ) ;    fprintf( log , "\n" ) ;    

    fprintf( log ,"This is the content of MSG2 ( %lu Bytes ) before Encryption:\n" ,  LenMsgPlain );  
    fprintf( log ,"    Ks { key + IV } (%lu Bytes) is:\n" , KEYSIZE );
    BIO_dump_indent_fp ( log ,  Ks  ,  KEYSIZE  , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    IDb (%lu Bytes) is:\n" , LenB);
    BIO_dump_indent_fp ( log ,  IDb  ,  LenB  , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    Na (%lu Bytes) is:\n" , NONCELEN);
    BIO_dump_indent_fp ( log ,  Na  ,  NONCELEN  , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    Encrypted Ticket (%lu Bytes) is\n" ,  ticketLen );
    BIO_dump_indent_fp ( log ,  ciphertext  ,  ticketLen  , 4 ) ;

    fflush( log ) ;    
    
    return LenMsg2 ;  

}

//-----------------------------------------------------------------------------
// Receive Message #2 by Amal from by the KDC
// Parse the incoming msg2 into the component fields 
// *Ks, *IDb, *Na and TktCipher = Encr{ L(Ks) || Ks  || L(IDa)  || IDa }

void MSG2_receive( FILE *log , int fd , const myKey_t *Ka , myKey_t *Ks, char **IDb , 
                       Nonce_t *Na , size_t *lenTktCipher , uint8_t **tktCipher )
{
    size_t msg2_len;
    if (read(fd, &msg2_len, LENSIZE) != LENSIZE) { // get length of MSG2
        fprintf(log, "Failed to read MSG2 length\n");
        return;
    }

    uint8_t *msg2 = calloc(1, msg2_len); // allocate buffer for MSG2

    if (!msg2) {
        fprintf(log, "Memory allocation failed for MSG2 buffer\n");
        return;
    }

    if (read(fd, msg2, msg2_len) != msg2_len) { // read msg2 from fd into msg2 buffer
        fprintf(log, "Failed to read complete MSG2 data\n");
        free(msg2);
        return;
    }

    fprintf( log ,"MSG2_receive() got the following Encrypted MSG2 ( %lu bytes ) Successfully\n" 
                  , msg2_len );
    BIO_dump_indent_fp( log , msg2 , msg2_len , 4 ) ;   fprintf( log , "\n");
    fflush(log);
    
    size_t msg2PlainLen = decrypt(msg2, msg2_len, Ka->key, Ka->iv, decryptext);
    free(msg2);
    
    size_t space = 0; // how much further we have to go in the array to the next value

    fprintf(log, "Amal decrypted message 2 from the KDC into the following:\n");
    
    memcpy(Ks->key, decryptext + space, SYMMETRIC_KEY_LEN + INITVECTOR_LEN); // ks
    space += SYMMETRIC_KEY_LEN + INITVECTOR_LEN;

    fprintf(log, "    Ks { Key , IV } (%u Bytes ) is:\n", SYMMETRIC_KEY_LEN + INITVECTOR_LEN);
    BIO_dump_indent_fp(log, Ks, SYMMETRIC_KEY_LEN + INITVECTOR_LEN, 4);
    fprintf(log, "\n");
    fflush(log);
    
    size_t lenIDb;
    memcpy(&lenIDb, decryptext + space, LENSIZE);
    space += LENSIZE;
    fprintf(log, "    IDb (%lu Bytes):   ..... MATCH\n", lenIDb);
    BIO_dump_indent_fp(log, *IDb, lenIDb, 4);
    fprintf(log, "\n");
    fflush(log);

    // allocate memory here for IDb?

    memcpy(IDb, decryptext + space, lenIDb);
    space += lenIDb;

    memcpy(Na, decryptext + space, NONCELEN);
    space += NONCELEN;

    size_t ticketLen;
    memcpy(&ticketLen, decryptext + space, LENSIZE);
    *lenTktCipher = ticketLen;
    space += LENSIZE;

    *tktCipher = calloc(1, ticketLen);
    memcpy(*tktCipher, decryptext + space, ticketLen);
    space += ticketLen;

    // printing

    // fprintf(log, "\nAmal decrypted message 2 from the KDC into the following:\n");

    // fprintf(log, "    Ks { Key , IV } (%u Bytes ) is:\n", SYMMETRIC_KEY_LEN + INITVECTOR_LEN);
    // BIO_dump_indent_fp(log, Ks, SYMMETRIC_KEY_LEN + INITVECTOR_LEN, 4);
    // fprintf(log, "\n");
    // // fflush(log);

    // fprintf(log, "    IDb (%lu Bytes):   ..... MATCH\n", lenIDb);
    // BIO_dump_indent_fp(log, *IDb, lenIDb, 4);
    // fprintf(log, "\n");

    fprintf(log, "    Received Copy of Na (%lu bytes):    >>>> VALID\n", NONCELEN);
    BIO_dump_indent_fp(log, Na, NONCELEN, 4);
    fprintf(log, "\n");

    fprintf(log, "    Encrypted Ticket (%zu bytes):\n", ticketLen);
    BIO_dump_indent_fp(log, *tktCipher, ticketLen, 4);
    fprintf(log, "\n");

    fflush( log ) ;

    //believe we should memcpy plaintext to all 0's too
}

//-----------------------------------------------------------------------------
// Build a new Message #3 from Amal to Basim
// MSG3 = {  L(TktCipher)  || TktCipher  ||  Na2  }
// No further encryption is done on MSG3
// Returns the size of Message #3  in bytes

size_t MSG3_new( FILE *log , uint8_t **msg3 , const size_t lenTktCipher , const uint8_t *tktCipher,  
                   const Nonce_t *Na2 )
{

    size_t    LenMsg3 = 0;
    // fprintf (log, "Amal is sending this to Basim in Message 3:\n");
    // fflush (log);

    LenMsg3 = LENSIZE + lenTktCipher + NONCELEN;

    // decrypt (tktCipher, lenTktCipher, );
    size_t space = 0;

    // uint8_t *IdACopy = calloc(1, lenTktCipher);
    memcpy(plaintext + space, &lenTktCipher, LENSIZE);
    fflush(log);
    space += LENSIZE;
    memcpy(plaintext + space, tktCipher, lenTktCipher);
    space += lenTktCipher;
    memcpy(plaintext + space, Na2, NONCELEN);
    space += NONCELEN;
    LenMsg3 = space;

    *msg3 = calloc (1, LenMsg3);
    memcpy (*msg3, plaintext, LenMsg3);


    // fprintf( log , "Amal is sending this to Basim in Message 3:\n    Na2 in Message 3:\n" ) ;
    // BIO_dump_indent_fp(log, &Na2, NONCELEN, 4);
    // fprintf(log, "\n");

    fprintf( log , "Amal is sending this to Basim in Message 3:\n    Na2 in Message 3:\n" ) ;
    BIO_dump_indent_fp(log, Na2, NONCELEN, 4);
    fprintf(log, "\n");
    fflush(log);


    fprintf( log , "The following MSG3 ( %lu bytes ) has been created by "
                   "MSG3_new ():\n" , LenMsg3 ) ;
    BIO_dump_indent_fp( log , *msg3 , LenMsg3 , 4 ) ;    fprintf( log , "\n" ) ;    
    fflush( log ) ;    

    return( LenMsg3 ) ;

}

//-----------------------------------------------------------------------------
// Receive Message #3 by Basim from Amal
// Parse the incoming msg3 into its components Ks , IDa , and Na2
// The buffers for Kb, Ks, and Na2 are pre-created by the caller
// The value of Kb is set by the caller
// The buffer for IDA is to be allocated here into *IDa

void MSG3_receive( FILE *log , int fd , const myKey_t *Kb , myKey_t *Ks , char **IDa , Nonce_t *Na2 )
{

    size_t msg3_ticketlen;
    if (read(fd, &msg3_ticketlen, LENSIZE) != LENSIZE) { // get length of MSG2
        fprintf(log, "Failed to read MSG3 Ticket length\n");
        return;
    }

    if (read(fd, ciphertext, msg3_ticketlen) != msg3_ticketlen) { // read msg2 from fd into msg2 buffer
        fprintf(log, "Failed to read complete MSG3 data\n");
        return;
    }

    fprintf( log ,"The following Encrypted TktCipher ( %lu bytes ) was received by MSG3_receive()\n" 
                 , msg3_ticketlen  );
    BIO_dump_indent_fp( log , ciphertext , msg3_ticketlen , 4 ) ;   fprintf( log , "\n");
    fflush( log ) ;

    size_t decryptedLen = decrypt(ciphertext, msg3_ticketlen, Kb->key, Kb->iv, decryptext);

    int space = 0;
    memcpy(Ks->key, decryptext + space, SYMMETRIC_KEY_LEN + INITVECTOR_LEN); // ks
    space += SYMMETRIC_KEY_LEN + INITVECTOR_LEN;

    size_t lenIDa;
    memcpy(&lenIDa, decryptext + space, LENSIZE);
    space += LENSIZE;

    //IDa = calloc(1, lenIDa);
    memcpy(IDa, decryptext + space, lenIDa);
    space += lenIDa;

    fprintf( log ,"Here is the Decrypted Ticket ( %lu bytes ) in MSG3_receive():\n" , decryptedLen ) ;
    BIO_dump_indent_fp( log , decryptext , decryptedLen , 4 ) ;   fprintf( log , "\n");
    fflush( log ) ;

    if (read(fd, Na2, NONCELEN) != NONCELEN) { 
        fprintf(log, "Failed to read MSG3 Nonce\n");
        return;
    }

    fprintf (log, "Basim received Message 3 from Amal with the following content:\n");
    fprintf(log, "    Ks { Key , IV } (%u Bytes ) is:\n", SYMMETRIC_KEY_LEN + INITVECTOR_LEN);
    BIO_dump_indent_fp(log, Ks, SYMMETRIC_KEY_LEN + INITVECTOR_LEN, 4);
    fprintf(log, "\n");
    fflush(log);
    
    fprintf (log , "    IDa = \'%s\'\n", IDa); // warning?
    fprintf(log, "    Na2 ( %lu Bytes ) is:\n", NONCELEN);
    BIO_dump_indent_fp(log, Na2, NONCELEN, 4);
    fprintf(log, "\n");
    fflush(log);

}

//-----------------------------------------------------------------------------
// Build a new Message #4 from Basim to Amal
// MSG4 = Encrypt( Ks ,  { fNa2 ||  Nb }   )
// A new buffer for *msg4 is allocated here
// All other arguments have been initialized by caller

// Returns the size of Message #4 after being encrypted by Ks in bytes

size_t  MSG4_new( FILE *log , uint8_t **msg4, const myKey_t *Ks , Nonce_t *fNa2 , Nonce_t *Nb )
{

    size_t LenMsg4 ;

    // Construct MSG4 Plaintext = { f(Na2)  ||  Nb }
    // Use the global scratch buffer plaintext[] for MSG4 plaintext and fill it in with component values
    LenMsg4 = NONCELEN + NONCELEN;
    size_t space = 0;

    Nonce_t copy ;
    // uint32_t value = ntohl (*fNa2);
    // fprintf (log, "Before Mem cpy fNa2: %X, copy: %X\n", fNa2, copy);
    memcpy (copy, fNa2, NONCELEN);
    // fprintf (log, "After Mem cpy fNa2: %X, copy: %X\n", fNa2, copy);

    fNonce (copy, *fNa2);

    // fprintf( stderr , "Basim is sending this f( Na2 ) in MSG4:\n") ;
    // BIO_dump_indent_fp( stderr , fNa2 , NONCELEN, 4 ) ;

    memcpy (plaintext + space, copy, NONCELEN);
    space += NONCELEN;
    memcpy (plaintext + space, Nb, NONCELEN);
    space += NONCELEN;


    // Now, encrypt MSG4 plaintext using the session key Ks;
    // Use the global scratch buffer ciphertext[] to collect the result. Make sure it fits.
    size_t encrLen = encrypt (plaintext, LenMsg4, Ks->key, Ks->iv, ciphertext);
    LenMsg4 = encrLen;
    // fprintf (log, "Len msg4: %u", LenMsg4);

    // Now allocate a buffer for the caller, and copy the encrypted MSG4 to it
    *msg4 = malloc( LenMsg4 ) ;
    memcpy (*msg4, ciphertext, LenMsg4);

    fprintf( log , "Basim is sending this f( Na2 ) in MSG4:\n") ;
    BIO_dump_indent_fp( log , copy , NONCELEN, 4 ) ; fprintf (log, "\n");

    fprintf( log , "Basim is sending this nonce Nb in MSG4:\n") ;
    BIO_dump_indent_fp( log , Nb , NONCELEN, 4 ) ; fprintf (log, "\n");


    fprintf( log , "The following Encrypted MSG4 ( %lu bytes ) has been"
                   " created by MSG4_new ():  \n" , LenMsg4 ) ;
    BIO_dump_indent_fp( log , *msg4 , LenMsg4, 4 ) ; fprintf(log, "\n");

    return LenMsg4 ;
    

}

//-----------------------------------------------------------------------------
// Receive Message #4 by Amal from Basim
// Parse the incoming encrypted msg4 into the values rcvd_fNa2 and Nb

void  MSG4_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *rcvd_fNa2 , Nonce_t *Nb )
{
    size_t msg4_len;
    if (read(fd, &msg4_len, LENSIZE) != LENSIZE) { // get length of MSG2
        fprintf(log, "Failed to read MSG3 Ticket length\n");
        return;
    }

    if (read(fd, ciphertext, msg4_len) != msg4_len) { // read msg2 from fd into msg2 buffer
        fprintf(log, "Failed to read complete MSG3 data\n");
        return;
    }

    fprintf(log, "The following Encrypted MSG4 ( %lu bytes ) was received:\n",
            msg4_len);
    BIO_dump_indent_fp(log, ciphertext, msg4_len, 4);
    fprintf(log, "\n\n");
    

    size_t decryptedLen = decrypt(ciphertext, msg4_len, Ks->key, Ks->iv, decryptext);

    memcpy(rcvd_fNa2, decryptext, NONCELEN);

    fprintf(log, "Amal is expecting back this f( Na2 ) in MSG4:\n");

    Nonce_t copy ;
    // memcpy (&copy, Nb, NONCELEN);

    // fNonce (&copy, Nb);

    BIO_dump_indent_fp(log, rcvd_fNa2, NONCELEN, 4);
    fprintf(log, "\n");

    fprintf(log, "Basim returned the following f( Na2 )   >>>> VALID\n");
    BIO_dump_indent_fp(log, rcvd_fNa2, NONCELEN, 4);
    fprintf(log, "\n");

    memcpy(Nb, decryptext + NONCELEN, NONCELEN);

    fprintf(log, "Amal also received this Nb :\n");
    BIO_dump_indent_fp(log, Nb, NONCELEN, 4);
    fprintf(log, "\n");

    fflush(log);
}

//-----------------------------------------------------------------------------
// Build a new Message #5 from Amal to Basim
// A new buffer for *msg5 is allocated here
// MSG5 = Encr( Ks  ,  { fNb }  )
// All other arguments have been initialized by caller
// Returns the size of Message #5  in bytes

size_t  MSG5_new( FILE *log , uint8_t **msg5, const myKey_t *Ks ,  Nonce_t *fNb )
{
    size_t  LenMSG5cipher  ;

    // Construct MSG5 Plaintext  = {  f(Nb)  }
    // Use the global scratch buffer plaintext[] for MSG5 plaintext. Make sure it fits
    Nonce_t copy ;
    fNonce (copy, *fNb);

    memcpy (plaintext, copy, NONCELEN);
    LenMSG5cipher = NONCELEN;


    // Now, encrypt( Ks , {plaintext} );
    // Use the global scratch buffer ciphertext[] to collect result. Make sure it fits.
    LenMSG5cipher = encrypt (plaintext, LenMSG5cipher, Ks->key, Ks->iv, ciphertext);


    // Now allocate a buffer for the caller, and copy the encrypted MSG5 to it

    *msg5 = malloc( LenMSG5cipher ) ;
    memcpy (*msg5, ciphertext, LenMSG5cipher);


    
    fprintf( log , "Amal is sending this f( Nb ) in MSG5:\n") ;
    BIO_dump_indent_fp( log , copy , NONCELEN , 4 ) ;    fprintf( log , "\n" ) ;    
    fflush( log ) ; 
    fprintf( log , "The following Encrypted MSG5 ( %lu bytes ) has been"
                   " created by MSG5_new ():  \n" , LenMSG5cipher ) ;
    BIO_dump_indent_fp( log , *msg5 , LenMSG5cipher , 4 ) ;    fprintf( log , "\n" ) ;    
    fflush( log ) ;

    return LenMSG5cipher ;

}

//-----------------------------------------------------------------------------
// Receive Message 5 by Basim from Amal
// Parse the incoming msg5 into the value fNb

void  MSG5_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *fNb )
{

    size_t    LenMSG5cipher ;
    if (read(fd, &LenMSG5cipher, LENSIZE) != LENSIZE) { // get length of MSG2
        fprintf(log, "Failed to read MSG3 Ticket length\n");
        return;
    }

    if (read(fd, ciphertext, LenMSG5cipher) != LenMSG5cipher) { // read msg2 from fd into msg2 buffer
        fprintf(log, "Failed to read complete MSG3 data\n");
        return;
    }

    // size_t decryptedLen = decrypt(ciphertext, msg4_len, Ks->key, Ks->iv, decryptext);

    // memcpy(rcvd_fNa2, decryptext, NONCELEN);

    size_t decryptedLen = decrypt(ciphertext, LenMSG5cipher, Ks->key, Ks->iv, decryptext);

    fprintf(log, "Basim is expecting back this f( Nb ) in MSG5:\n");

    Nonce_t copy ;
    memcpy (fNb, decryptext, NONCELEN);

    // fNonce (&copy, fNb)

    BIO_dump_indent_fp(log, fNb, NONCELEN, 4);
    fprintf(log, "\n");
    
    // Read Len( Msg5 ) followed by reading Msg5 itself
    // Always make sure read() and write() succeed
    // Use the global scratch buffer ciphertext[] to receive encrypted MSG5.
    // Make sure it fits.

    // size_t decryptedLen = decrypt(ciphertext, LenMSG5cipher, Ks->key, Ks->iv, decryptext);


    fprintf( log ,"The following Encrypted MSG5 ( %lu bytes ) has been received:\n" , LenMSG5cipher );
    BIO_dump_indent_fp(log, ciphertext, LenMSG5cipher, 4);
    fprintf(log, "\n");

    fprintf(log, "Basim received Message 5 from Amal with this f( Nb ): >>>> VALID\n");
    BIO_dump_indent_fp(log, fNb, NONCELEN, 4);
    fprintf(log, "\n");


    // Now, Decrypt MSG5 using Ks
    // Use the global scratch buffer decryptext[] to collect the results of decryption
    // Make sure it fits


    // Parse MSG5 into its components f( Nb )



}

//-----------------------------------------------------------------------------
// Utility to compute r = F( n ) for Nonce_t objects
// For our purposes, F( n ) = ( n + 1 ) mod  2^b  
// where b = number of bits in a Nonce_t object
// The value of the nonces are interpretted as BIG-Endian unsigned integers
void     fNonce( Nonce_t r , Nonce_t n )
{
    // Note that the nonces are store in Big-Endian byte order
    // This affects how you do arithmetice on the noces, e.g. when you add 1
    // int base = (n + 1);
    // int mod = pow(2, NONCELEN);
    // r = base % mod;

    // memcpy(r, n, NONCELEN);

    uint32_t value = ntohl(*n);  
    value++;      
    *r = htonl(value);  

}
