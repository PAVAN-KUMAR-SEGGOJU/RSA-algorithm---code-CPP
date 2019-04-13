
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <gmp.h>
#include <sys/time.h>


#define BITSTRENGTH  1024               /* size of modulus (n) in bits */
#define PRIMESIZE    (BITSTRENGTH / 2)  /* size of the primes p and q  */


/* Declare global variables */

mpz_t d,e,n;
mpz_t M,c;


/* Declare time-related variables */

struct timeval tv1,tv2;
struct timeval tvdiff;
struct timezone tz;


/* Declare core routines */

void RSA_generateKeys();
int  RSA_checkKeys();
void RSA_encrypt();
void RSA_decrypt();


/* Initialization related routines */

void initializeGMP();
void clearGMP();
void initializeRandom();


/* Timing routine */
void timediff(struct timeval*,struct timeval*,struct timeval*);


/* Helper routines */
inline void process(char*);
inline void encrypt(char*,FILE*);



/* Main subroutine */
int main()
{
    /* Initialize the GMP integers first */
    initializeGMP();

    /*
    *  Check existence of key files : ~/.rsapublic 
    *  and ~/.rsaprivate else generate new keys and file 
    */

    if(!RSA_checkKeys())
    {
        printf("Creating new RSA Key Files...\n\n");
        RSA_generateKeys();
    }

    /* Show menu */
    int choice = -1;

    while(choice!=3)
    {
        printf("\n\n");

        printf("\n1. Encrypt... ");
        printf("\n2. Decrypt... ");
        printf("\n3. Quit... ");

        printf("\n\nEnter your choice (1-3) : ");
        scanf("%d",&choice);

        switch(choice)
        {
            case 1  :   RSA_encrypt();
                        break;

            case 2  :   RSA_decrypt();
                        break;

            case 3  :   return(0);

            default :   printf("\nUndefined choice.");
        }
    }

    /* Clear the GMP integers */
    clearGMP();

    return 0;
}



void initializeGMP()
{
    /* Initialize all the GMP integers once and for all */

    mpz_init(d);
    mpz_init(e);
    mpz_init(n);

    mpz_init(M);
    mpz_init(c);
}



void clearGMP()
{
    /* Clean up the GMP integers */

    mpz_clear(d);
    mpz_clear(e);
    mpz_clear(n);

    mpz_clear(M);
    mpz_clear(c);
}



void initializeRandom()
{
    /* This initializes the random number generator */

    /* sleep for one second (avoid calls in the same second) */
    sleep(1);

    /* Set seed for rand() by system time() ... */
    unsigned int time_elapsed;
    time((time_t*)&time_elapsed);
    srand(time_elapsed);
}



void timediff(struct timeval* a,struct timeval* b,struct timeval* result)
{
    /* This function calculates and returns the time
    *  difference between two timeval structs
    */

    (result)->tv_sec  = (a)->tv_sec  - (b)->tv_sec;
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;

    if((result)->tv_usec < 0)
    {
        --(result)->tv_sec;
        (result)->tv_usec += 1000000;
    }
}



int RSA_checkKeys()
{
    /* This function checks whether the keys exist 
    *  in the file ~/.rsaprivate and ~/.rsapublic
    */

    char publicFile[100];
    char privateFile[100];

    strcpy(publicFile,getenv("HOME"));
    strcpy(privateFile,getenv("HOME"));

    strcat(publicFile,"/.rsapublic");
    strcat(privateFile,"/.rsaprivate");

    FILE* fpublic  = fopen(publicFile,"r");
    FILE* fprivate = fopen(privateFile,"r");

    if((!fpublic) || (!fprivate))
    {
        /* Key files do not exist */
        return 0;
    }


    printf("\nUsing RSA Key Files : \n\n");
    printf("\nPublic Key File  : %s",publicFile);
    printf("\nPrivate Key File : %s",privateFile);

    char d_str[1000];
    char e_str[100];
    char n_str[1000];


    /* Get keys */
    fscanf(fpublic,"%s\n",e_str);
    fscanf(fpublic,"%s\n",n_str);

    fscanf(fprivate,"%s\n",d_str);

    mpz_set_str(d,d_str,10);
    mpz_set_str(e,e_str,10);
    mpz_set_str(n,n_str,10);

    fclose(fpublic);
    fclose(fprivate);

    return 1;
}



void RSA_generateKeys()
{
    /* This function creates the keys. The basic algorithm is...
    *
    *  1. Generate two large distinct primes p and q randomly
    *  2. Calculate n = pq and x = (p-1)(q-1)
    *  3. Select a random integer e (1<e<x) such that gcd(e,x) = 1
    *  4. Calculate the unique d such that ed = 1(mod x)
    *  5. Public key pair : (e,n), Private key pair : (d,n)
    *
    */

    /* initialize random seed */
    initializeRandom();

    /* first, record the start time */
    if(gettimeofday(&tv1,&tz)!=0)
        printf("\nWarning : could not gettimeofday() !");

    /*
    *  Step 1 : Get two large (512 bits) primes.
    */

    mpz_t p,q;

    mpz_init(p);
    mpz_init(q);

    char* p_str = new char[PRIMESIZE+1];
    char* q_str = new char[PRIMESIZE+1];

    p_str[0] = '1';
    q_str[0] = '1';

    for(int i=1;i<PRIMESIZE;i++)
        p_str[i] = (int)(2.0*rand()/(RAND_MAX+1.0)) + 48;

    for(int i=1;i<PRIMESIZE;i++)
        q_str[i] = (int)(2.0*rand()/(RAND_MAX+1.0)) + 48;

    p_str[PRIMESIZE] = '\0';
    q_str[PRIMESIZE] = '\0';

    mpz_set_str(p,p_str,2);
    mpz_set_str(q,q_str,2);

    mpz_nextprime(p,p);
    mpz_nextprime(q,q);

    mpz_get_str(p_str,10,p);
    mpz_get_str(q_str,10,q);

    printf("Random Prime 'p' = %s\n",p_str);
    printf("Random Prime 'q' = %s\n",q_str);

    /*
    *  Step 2 : Calculate n (=pq) ie the 1024 bit modulus
    *  and x (=(p-1)(q-1)).
    */

    char n_str[1000];

    mpz_t x;

    mpz_init(x);


    /* Calculate n... */

    mpz_mul(n,p,q);

    mpz_get_str(n_str,10,n);
    printf("\nn = %s\n",n_str);


    /* Calculate x... */

    mpz_t p_minus_1,q_minus_1;

    mpz_init(p_minus_1);
    mpz_init(q_minus_1);

    mpz_sub_ui(p_minus_1,p,(unsigned long int)1);
    mpz_sub_ui(q_minus_1,q,(unsigned long int)1);

    mpz_mul(x,p_minus_1,q_minus_1);


    /*
    *  Step 3 : Get small odd integer e such that gcd(e,x) = 1.
    */

    mpz_t gcd;
    mpz_init(gcd);

    /*
    *  Assuming that 'e' will not exceed the range
    *  of a long integer, which is quite a reasonable
    *  assumption.
    */

    unsigned long int e_int = 65537;

    while(true)
    {
        mpz_gcd_ui(gcd,x,e_int);

        if(mpz_cmp_ui(gcd,(unsigned long int)1)==0)
            break;

        /* try the next odd integer... */
        e_int += 2;
    }

    mpz_set_ui(e,e_int);


    /*
    *  Step 4 : Calculate unique d such that ed = 1(mod x)
    */


    char d_str[1000];

    if(mpz_invert(d,e,x)==0)
    {
        printf("\nOOPS : Could not find multiplicative inverse!\n");
        printf("\nTrying again...");
        RSA_generateKeys();

    }

    mpz_get_str(d_str,10,d);

    printf("\n\n");

    /*
    *  Print the public and private key pairs...
    */

    printf("\nPublic Keys (e,n): \n\n");
    printf("\nValue of 'e' : %ld",e_int);
    printf("\nValue of 'n' : %s ",n_str);

    printf("\n\n");

    printf("\nPrivate Key : \n\n");
    printf("\nValue of 'd' : %s",d_str);

    /* get finish time of key generation */
    if(gettimeofday(&tv2,&tz)!=0)
        printf("\nWarning : could not gettimeofday() !");

    timediff(&tv2,&tv1,&tvdiff);

    printf("\nKey Generation took (including I/O) ...\n");
    printf("\n%-15s : %ld","Seconds",tvdiff.tv_sec);
    printf("\n%-15s : %ld","Microseconds",tvdiff.tv_usec);


    /* Write values to file $HOME/.rsapublic and $HOME/.rsaprivate */

    char publicFile[100];
    char privateFile[100];

    strcpy(publicFile,getenv("HOME"));
    strcpy(privateFile,getenv("HOME"));

    strcat(publicFile,"/.rsapublic");
    strcat(privateFile,"/.rsaprivate");

    FILE* fpublic  = fopen(publicFile,"w");
    FILE* fprivate = fopen(privateFile,"w");

    if((!fpublic) || (!fprivate))
    {
        fprintf(stderr,"FATAL: Could not write to RSA Key Files!");
        exit(1);
    }

    /* Write ~/.rsapublic */
    fprintf(fpublic,"%ld\n",e_int);
    fprintf(fpublic,"%s\n",n_str);

    /* Write ~/.rsaprivate */
    fprintf(fprivate,"%s\n",d_str);

    fclose(fpublic);
    fclose(fprivate);

    printf("\nWrote RSA Key Files ...\n");
    printf("\nPublic Key File  : %s",publicFile);
    printf("\nPrivate Key File : %s",privateFile);

    /* clean up the gmp mess */
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(x);
    mpz_clear(p_minus_1);
    mpz_clear(q_minus_1);
    mpz_clear(gcd);

}



void RSA_encrypt()
{
    /* The RSA Encryption routine */


    printf("RSA Encryption :\n\n");

    char pubkeyfile[200];   /* file containing public key */
    char infile[200];    /* filename to encrypt */
    char outfile[200];    /* filename to decrypt */
    FILE *fin,*fout;    /* file pointers */
    FILE *fpublic;        /* file pointer to public keyfile */

    int num;        /* number of characters
                   to encrypt together */

    int i;            /* string index */
    char chread;        /* character read */
    char stread[1000];    /* string read */

    char e_str[100],n_str[1000];

    /* Get public keys of recipient */
    printf("\nEnter file containing public key of recipient");
    printf("\nType '.' to use your own public key : ");

    strcpy(pubkeyfile,"");
    scanf("%s",pubkeyfile);

    if(strcmp(pubkeyfile,"."))
    {
        fpublic = fopen(pubkeyfile,"r");

        if(!fpublic)
        {
            fprintf(stderr,"FATAL: Could not read %s!",pubkeyfile);
            return;
        }

        fscanf(fpublic,"%s\n",e_str);
        fscanf(fpublic,"%s\n",n_str);

        mpz_set_str(e,e_str,10);
        mpz_set_str(n,n_str,10);

    }
    else
        printf("\nWARNING : Encrypting using your own public key!\n");

    printf("\nEnter filename to encrypt :");
    scanf("%s",infile);

    fin = fopen(infile,"r");

    if(!fin)
    {
        fprintf(stderr,"FATAL : Could not open %s for reading",infile);
        return;
    }

    printf("Enter filename to encrypt to :");
    scanf("%s",outfile);

    fout = fopen(outfile,"w");

    if(!fout)
    {
        fprintf(stderr,"FATAL : Could not open %s for writing",outfile);
        return;
    }

    printf("Enter number of characters to encrypt together :");
    scanf("%d",&num);

    if(num<1 || num>100)
    {
        /* safest numbers are in the range 1-100 for 1024 bit RSA */

        if(num<1)
        {
            fprintf(stderr,"Invalid input!");
            return;
        }
        else
            fprintf(stderr,"WARNING : Possibly out of range!");
    }


    /* Get time before encryption */
    if(gettimeofday(&tv1,&tz)!=0)
        fprintf(stderr,"\nWARNING : could not gettimeofday() !");


    i = 0;
    chread = 'a';

    do
    {

        chread = fgetc(fin);

        if(chread==EOF)
        {
            if(i!=0)
            {
                stread[i] = '\0';
                encrypt(stread,fout);
            }
        }
        else if(i==num-1)
        {
            stread[i] = chread;
            stread[i+1] = '\0';
            encrypt(stread,fout);
            i = 0;

        }
        else
        {
            stread[i] = chread;
            i++;
        }

    }while(chread!=EOF);

    /* Get time after encryption */
    if(gettimeofday(&tv2,&tz)!=0)
        printf("\nWarning : could not gettimeofday() !");

    timediff(&tv2,&tv1,&tvdiff);

    printf("\nEncryption took...\n");

    printf("\n%-15s : %ld","Seconds",tvdiff.tv_sec);
    printf("\n%-15s : %ld","Microseconds",tvdiff.tv_usec);

    fclose(fin);
    fclose(fout);
}



inline void encrypt(char* msg,FILE* fout)
{
    /* This function actually does the encrypting of each message */

    unsigned int i;
    int tmp;
    char tmps[4];
    char* intmsg = new char[strlen(msg)*3 + 1];


    /* Here, (mpz_t) M is the messsage in gmp integer 
    *  and (mpz_t) c is the cipher in gmp integer */

    char ciphertext[1000];

    strcpy(intmsg,"");

    for(i=0;i<strlen(msg);i++)
    {
        tmp = (int)msg[i];

        /* print it in a 3 character wide format */
        sprintf(tmps,"%03d",tmp);

        strcat(intmsg,tmps);
    }

    mpz_set_str(M,intmsg,10);

    /* free memory claimed by intmsg */
    delete [] intmsg;

    /* c = M^e(mod n) */
    mpz_powm(c,M,e,n);

    /* get the string representation of the cipher */
    mpz_get_str(ciphertext,10,c);

    /* write the ciphertext to the output file */
    fprintf(fout,"%s\n",ciphertext);
}




void RSA_decrypt()
{
    /* The RSA decryption routine */

    printf("RSA Decryption:\n\n");

    char file[200];        /* filename of file to decrypt */
    FILE* fp;        /* file pointer to decrypt */
    char ciphertext[1000];    /* ciphertext */

    /* Here, (mpz_t) c is the cipher in gmp integer  
    *  and (mpz_t) M is the message in gmp integer */

    char decrypted[1000];    /* decypted text */

    printf("Enter name of file to decrypt :");
    scanf("%s",file);


    fp = fopen(file,"r");

    if(!fp)
    {
        fprintf(stderr,"FATAL : Could not open %s for reading",file);
        return;
    }

    /* Get time before decryption */
    if(gettimeofday(&tv1,&tz)!=0)
        printf("\nWarning : could not gettimeofday() !");

    while(fscanf(fp,"%s\n",ciphertext)>0)
    {
        mpz_set_str(c,ciphertext,10);

        /* M = c^d(mod n) */
        mpz_powm(M,c,d,n);

        mpz_get_str(decrypted,10,M);

        process(decrypted);
    }

    /* Get time after decription */
    if(gettimeofday(&tv2,&tz)!=0)
        printf("\nWarning : could not gettimeofday() !");

    timediff(&tv2,&tv1,&tvdiff);

    printf("\nDecryption took... (including output)\n");
    printf("\n%-15s : %ld","Seconds",tvdiff.tv_sec);
    printf("\n%-15s : %ld","Microseconds",tvdiff.tv_usec);
}



inline void process(char* str)
{
    /* This function shows the decrypted integer 
    *  message as an understandable text string 
    */

    unsigned int i=0;
    int tmpnum;
    char strmod[1000];

    /* make the message length an integral multiple
    *  of 3 by adding zeroes to the left if required
    */

    if(strlen(str)%3 == 1)
    {
        strcpy(strmod,"00");
        strcat(strmod,str);
    }
    else if(strlen(str)%3 == 2)
    {
        strcpy(strmod,"0");
        strcat(strmod,str);
    }
    else
        strcpy(strmod,str);


    while(i<=strlen(strmod)-3)
    {
        tmpnum = strmod[i] - 48;
        tmpnum = 10*tmpnum + (strmod[i+1] - 48);
        tmpnum = 10*tmpnum + (strmod[i+2] - 48);

        i += 3;

        printf("%c",tmpnum);
    }
}
