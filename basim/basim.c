/*----------------------------------------------------------------------------
pa-04_PartTwo:  Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   basim.c

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

// Generate random nonces for Basim
void  getNonce4Basim( int which , Nonce_t  value )
{
	// Normally we generate random nonces using
	// RAND_bytes( (unsigned char *) value , NONCELEN  );
	// However, for grading purpose, we will use fixed values

	switch ( which ) 
	{
		case 1:		// the first and Only nonce
			value[0] = 0x66778899 ;
			break ;

		default:	// Invalid agrument. Must be either 1 or 2
			fprintf( stderr , "\n\nBasim trying to create an Invalid nonce\n exiting\n\n");
			exit(-1);
	}
}

//*************************************
// The Main Loop
//*************************************
int main ( int argc , char * argv[] )
{

    int       fd_A2B , fd_B2A   ;
    FILE     *log ;

    char *developerName = "Code by Dormady & Parcell" ;

    fprintf( stdout , "Starting Basim's     %s\n" , developerName ) ;

    if( argc < 3 )
    {
        printf("\nMissing command-line file descriptors: %s <getFr. Amal> "
               "<sendTo Amal>\n\n", argv[0]) ;
        exit(-1) ;
    }

    fd_A2B    = atoi(argv[1]) ;  // Read from Amal   File Descriptor
    fd_B2A    = atoi(argv[2]) ;  // Send to   Amal   File Descriptor

    log = fopen("basim/logBasim.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "Basim's %s. Could not create log file\n" , developerName ) ;
        exit(-1) ;
    }

    BANNER( log ) ;
    fprintf( log , "Starting Basim\n"  ) ;
    BANNER( log ) ;

    // changed to match log file...
    fprintf( log , "\n<readFr. Amal> FD=%d , <sendTo Amal> FD=%d\n\n" , fd_A2B , fd_B2A );

    // Get Basim's master keys with the KDC
    myKey_t   Kb ;    // Basim's master key with the KDC    

    if(getKeyFromFile("basim/basimKey.bin", &Kb) == 0){
        fprintf( log, "\nCould not get Basim's Master Key & IV.\n");
        fprintf( stderr, "\nCould not get Basim's Master Key & IV.\n");
        exit( -1 );
    } 
    fprintf( log , "Basim has this Master Kb { key , IV }\n");
    BIO_dump_indent_fp(log, &(Kb.key), SYMMETRIC_KEY_LEN, 4);
    fprintf( log , "\n" );
    BIO_dump_indent_fp(log, &(Kb.iv), INITVECTOR_LEN, 4);
    fprintf(log, "\n");
    // Use  getKeyFromFile( "basim/basimKey.bin" , .... ) )
	// On failure, print "\nCould not get Basim's Masker key & IV.\n" to both  stderr and the Log file
	// and exit(-1)
	// On success, print "Basim has this Master Kb { key , IV }\n" to the Log file
	// BIO_dump the Key IV indented 4 spaces to the righ
    // fprintf( log , "\n" );
	// BIO_dump the IV indented 4 spaces to the righ

    // Get Basim's pre-created Nonces: Nb
	Nonce_t   Nb;  
    getNonce4Basim (1, Nb);
	// Use getNonce4Basim () to get Basim's 1st and only nonce into Nb
    fprintf( log , "Basim will use this Nonce:  Nb\n"  ) ;
	// BIO_dump Nb indented 4 spaces to the righ
    BIO_dump_indent_fp( log , &Nb ,  NONCELEN, 4) ;
    fprintf( log , "\n" );

    fflush( log ) ;
    
    
    
    //*************************************
    // Receive  & Process   Message 3
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG3 Receive\n");
    BANNER( log ) ;

    myKey_t Ks;
    char *IDa;
    Nonce_t Na2;

    MSG3_receive( log , fd_A2B , &Kb , &Ks, &IDa, &Na2) ;

    //*************************************
    // Construct & Send    Message 4
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG4 New\n");
    BANNER( log ) ;
    size_t *LenMsg4 ;
    u_int8_t *msg4 ;
    Nonce_t fNa2;
    memcpy (&fNa2, &Na2, NONCELEN);

    LenMsg4 = MSG4_new (log, &msg4, &Ks, &fNa2, &Nb);

    write (fd_B2A, &LenMsg4, LENSIZE);
    write (fd_B2A, msg4, LenMsg4);

    fprintf (log, "Basim Sent the above MSG4 to Amal\n\n");

    //*************************************
    // Receive   & Process Message 5
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG5 Receive\n");
    BANNER( log ) ;

    Nonce_t fNb;

    MSG5_receive (log, fd_A2B, &Ks, &fNb);

    //*************************************   
    // Final Clean-Up
    //*************************************
end_:
    fprintf( log , "\nBasim has terminated normally. Goodbye\n" ) ;
    fclose( log ) ;  

    return 0 ;
}
