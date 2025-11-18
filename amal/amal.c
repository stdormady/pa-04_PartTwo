/*----------------------------------------------------------------------------
pa-04_PartTwo:  Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   amal.c

Written By: 
     1- Steve Dormady
	 2- Shea Parcell
Submitted on: 
     Insert the date of Submission here
----------------------------------------------------------------------------*/

#include <linux/random.h>
#include <time.h>
#include <stdlib.h>

#include "../myCrypto.h"

// Generate random nonces for Amal
void  getNonce4Amal( int which , Nonce_t  value )
{
	// Normally we generate random nonces using
	// RAND_bytes( (unsigned char *) value , NONCELEN  );
	// However, for grading purpose, we will use fixed values

	switch ( which ) 
	{
		case 1:		// the first nonce
			value[0] = 0x11223344 ;
			break ;

		case 2:		// the second nonce
			value[0] = 0xaabbccdd ;		
			break ;

		default:	// Invalid agrument. Must be either 1 or 2
			fprintf( stderr , "\n\nAmal trying to create an Invalid nonce\n exiting\n\n");
			exit(-1);
	}
}
	
//*************************************
// The Main Loop
//*************************************
int main ( int argc , char * argv[] )
{
    int      fd_A2K , fd_K2A , fd_A2B , fd_B2A  ;
    FILE    *log ;

    char *developerName = "Code by Dormady & Parcell" ;

    fprintf( stdout , "Starting Amal's      %s.\n" , developerName  ) ;
    
    if( argc < 5 )
    {
        printf("\nMissing command-line file descriptors: %s <getFr. KDC> <sendTo KDC> "
               "<getFr. Basim> <sendTo Basim>\n\n" , argv[0]) ;
        exit(-1) ;
    }
    fd_K2A    = atoi(argv[1]) ;  // Read from KDC    File Descriptor
    fd_A2K    = atoi(argv[2]) ;  // Send to   KDC    File Descriptor
    fd_B2A    = atoi(argv[3]) ;  // Read from Basim  File Descriptor
    fd_A2B    = atoi(argv[4]) ;  // Send to   Basim  File Descriptor

    log = fopen("amal/logAmal.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "\nAmal's  %s. Could not create my log file\n" , developerName  ) ;
        exit(-1) ;
    }

    BANNER( log ) ;
    fprintf( log , "Starting Amal\n" ) ;
    BANNER( log ) ;

    fprintf( log , "\n<readFrom KDC> FD=%d , <sendTo KDC> FD=%d , "
                   "<readFrom Basim> FD=%d , <sendTo Basim> FD=%d\n\n" , 
                   fd_K2A , fd_A2K , fd_B2A , fd_A2B );

    // Get Amal's master key with the KDC
    myKey_t  Ka ;  // Amal's master key with the KDC
    if (getKeyFromFile( "amal/amalKey.bin" , &Ka ) < 1)
    {
        fprintf(log, "\nCould not get Amal\'s Masker key & IV.\n");
        fprintf(stderr, "\nCould not get Amal\'s Masker key & IV.\n");
        exit(-1);
    }
    fprintf(log, "Amal has this Master Ka { key , IV }\n");

    BIO_dump_indent_fp( log , &Ka.key ,  SYMMETRIC_KEY_LEN, 4) ;
    fprintf(log, "\n");
    BIO_dump_indent_fp( log , &Ka.iv ,  INITVECTOR_LEN, 4) ;
    // Use  getKeyFromFile( "amal/amalKey.bin" , .... ) )
	// On failure, print "\nCould not get Amal's Masker key & IV.\n" to both  stderr and the Log file
	// and exit(-1)
	// On success, print "Amal has this Master Ka { key , IV }\n" to the Log file
	// BIO_dump the Key IV indented 4 spaces to the righ
    fprintf( log , "\n" );
	// BIO_dump the IV indented 4 spaces to the righ


    // Get Amal's pre-created Nonces: Na and Na2
	Nonce_t   Na , Na2; 
    getNonce4Amal (1, Na);
    getNonce4Amal (2, Na2);
    fprintf( log , "Amal will use these Nonces:  Na  and Na2\n"  ) ;
	// Use getNonce4Amal () to get Amal's 1st and second nonces into Na and Na2, respectively
	// BIO_dump Na indented 4 spaces to the righ
    BIO_dump_indent_fp( log , &Na ,  NONCELEN, 4) ;
    fprintf( log , "\n" );
	// BIO_dump Na2 indented 4 spaces to the righ

    BIO_dump_indent_fp( log , &Na2 ,  NONCELEN, 4) ;
    fprintf( log , "\n") ; 

    fflush( log ) ;

    //*************************************
    // Construct & Send    Message 1
    //*************************************
    BANNER( log ) ;
    fprintf( log , "         MSG1 New\n");
    BANNER( log ) ;

    char *IDa = "Amal is Hope", *IDb = "Basim is Smiley" ;
    size_t  LenMsg1 ;
    uint8_t  *msg1 ;
    
    LenMsg1 = MSG1_new( log , &msg1 , IDa , IDb , Na ) ;
    // fprintf(log, "%u", LenMsg1);
    
    // Send MSG1 to KDC via the appropriate pipe
    write(fd_A2K, msg1, LenMsg1);

    // MSG1_new (log, *msg1, IDa, IDb, Na);

   fprintf( log , "Amal sent message 1 ( %lu bytes ) to the KDC with:\n    "
                   "IDa ='%s'\n    "
                   "IDb = '%s'\n" , LenMsg1 , IDa , IDb ) ;
    fprintf( log , "    Na ( %lu Bytes ) is:\n" , NONCELEN ) ;
    BIO_dump_indent_fp(log, &Na, NONCELEN, 4);
    fprintf(log, "\n");
    // BIO_dump the nonce Na
    fflush( log ) ;

    // Deallocate any memory allocated for msg1
    free(msg1);
    
    //*************************************
    // Receive   &   Process Message 2
    //*************************************
	// PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG2 Receive\n");
    BANNER( log ) ;
    fflush(log);

    myKey_t Ks;
    size_t lenTktCipher;
    uint8_t *tktCipher;

    MSG2_receive ( log, fd_K2A, &Ka, &Ks, &IDb, &Na, &lenTktCipher, &tktCipher );
    fflush(log);
    //*************************************
    // Construct & Send    Message 3
    //*************************************
	// PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG3 New\n");
    BANNER( log ) ;
    fflush (log);

    size_t  LenMsg3 ;
    uint8_t  *msg3 ;

    LenMsg3 = MSG3_new( log , &msg3 , lenTktCipher , tktCipher , &Na2 ) ;

    
    // Send MSG2 to Basim via the appropriate pipe
    write(fd_A2B, LenMsg3, LENSIZE);
    write(fd_A2B, msg3, LenMsg3);

    fprintf(log, "Amal Sent the Message 3 ( %lu bytes ) to Basim\n\n", LenMsg3);
    fflush(log);

    //*************************************
    // Receive   & Process Message 4
    //*************************************
	// PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG4 Receive\n");
    BANNER( log ) ;

    Nonce_t rcvd;
    Nonce_t Nb;

    MSG4_receive(log, fd_B2A, &Ks, &rcvd, &Nb);

    //*************************************
    // Construct & Send    Message 5
    //*************************************
	// PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG5 New\n");
    BANNER( log ) ;
    size_t LenMsg5;
    uint8_t *msg5;

    LenMsg5 = MSG5_new (log, &msg5, &Ks, &Nb);

    if (write(fd_A2B, &LenMsg5, LENSIZE) != LENSIZE) {
        perror("write LenMsg5");
    }
    if (write(fd_A2B, msg5, LenMsg5) != (ssize_t)LenMsg5) {
        perror("write msg5");
    }

    fprintf (log, "Amal sent Message 5 ( %lu bytes ) to Basim\n", LenMsg5);
    free (msg5);

    //*************************************   
    // Final Clean-Up
    //*************************************  
end_:
    fprintf( log , "\nAmal has terminated normally. Goodbye\n" ) ;  
    fclose( log ) ;
    return 0 ;
}

