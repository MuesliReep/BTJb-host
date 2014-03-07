#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <curl/curl.h>
#include <termios.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>


/*
 *---------------------------------------------------------------------
 *
 * bitc_usage --
 *
 *---------------------------------------------------------------------
 */

static void
bitc_usage(void)
{
   printf("bitc: %s.\n"
          "Options:\n"
          " -c, --config     <configPath>  config file to use, default: ~/.bitc/main.cfg\n"
          " -d, --daemon                   daemon mode: no-ui\n"
          " -h, --help                     show this help message\n"
          " -n, --numPeers   <maxPeers>    number of peers to connect to, default is 5\n"
          " -t, --test       <param>       test suite: argument is the name of the test\n"
          " -T, --testnet                  connect to testnet\n"
          " -v, --version                  display version string and exit\n"
          BTC_CLIENT_DESC);
}

/*
 *---------------------------------------------------------------------
 *
 * main --
 *
 *---------------------------------------------------------------------
 */

int main(int argc, char *argv[])
{
	char *errStr = NULL;
	char *configPath = NULL;
	int maxPeers = 5;

	static const struct option long_opts [] = {
		{ "config",       required_argument,  0,  'c' },
		{ "daemon",       no_argument,        0,  'd' },
		{ "help",         no_argument,        0,  'h' },
		{ "numPeers",     required_argument,  0,  'n' },
		{ "test",         required_argument,  0,  't' },
		{ "testnet",      no_argument,        0,  'T' },
		{ "version",      no_argument,        0,  'v' },
		{  NULL,          0,                  0,   0  },
	};


	while ((c = getopt_long(argc, argv, "a:c:dehn:pt:Tuvz",
	                           long_opts, NULL)) != EOF) {
	      switch (c) {
	      case 'c': configPath = optarg;     break;
	      case 'd': withui = 0;              break;
	      case 'n': maxPeers = atoi(optarg); break;
	      case 't': testStr = optarg;        break;
	      case 'T': btc->testnet = 1;        break;
	      case 'v': bitc_version_and_exit(); break;
	      case 'h':
	      default:
	         bitc_usage();
	         return 0;
	      }
	}


	if (btc->testnet) {
		printf("Using testnet.\n");
		usleep(500 * 1000);
	}

	Log_SetLevel(1);
	{
	  char *login = util_getusername();
	  char *logFile;
	  logFile = safe_asprintf("/tmp/bitc-%s%s.log",
							  login ? login : "foo",
							  btc->testnet ? "-testnet" : "");
	  Log_Init(logFile);
	  free(logFile);
	  free(login);
	}
}
