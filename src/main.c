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
 *----------------------------------------------------------------
 *
 * bitc_load_config --
 *
 *----------------------------------------------------------------
 */

static int
bitc_load_config(struct config **config,
                 const char     *configPath)
{
   char *defaultPath = NULL;
   const char *path;
   int res;

   if (configPath == NULL) {
      char *dir = bitc_get_directory();
      defaultPath = safe_asprintf("%s/main.cfg", dir);
      free(dir);
      path = defaultPath;
   } else {
      path = configPath;
   }
   res = config_load(path, config);
   if (res) {
      Warning("Please create a minimal config: %s\n", path);
   }
   free(defaultPath);
   return res;
}

/*
 *------------------------------------------------------------------------
 *
 * bitc_check_config --
 *
 *------------------------------------------------------------------------
 */

static int
bitc_check_config(void)
{
   char *cfgPath;
   char *ctcPath;
   char *txPath;
   char *dir;
   int res = 0;

   dir = bitc_get_directory();
   cfgPath = safe_asprintf("%s/main.cfg",      dir);
   ctcPath = safe_asprintf("%s/contacts.cfg",  dir);
   txPath  = safe_asprintf("%s/tx-labels.cfg", dir);

   if (!file_exists(dir) || !file_exists(cfgPath)) {
      printf("\nIt looks like you're a new user. Welcome!\n"
             "\n"
             "Note that bitc uses the directory: ~/.bitc to store:\n"
             " - block headers:        ~/.bitc/headers.dat     -- ~ 20 MB\n"
             " - peer IP addresses:    ~/.bitc/peers.dat       --  ~ 2 MB\n"
             " - transaction database: ~/.bitc/txdb            --  < 1 MB\n"
             " - wallet keys:          ~/.bitc/wallet.cfg      --  < 1 KB\n"
             " - main config file:     ~/.bitc/main.cfg        --  < 1 KB\n"
             " - a contacts file:      ~/.bitc/contacts.cfg    --  < 1 KB\n"
             " - a tx-label file:      ~/.bitc/tx-labels.cfg   --  < 1 KB\n\n");
   }

   if (!file_exists(dir)) {
      Log(LGPFX" creating directory: %s\n", dir);
      res = file_mkdir(dir);
      if (res) {
         printf("Failed to create directory '%s': %s\n",
                dir, strerror(res));
         goto exit;
      }
      res = file_chmod(dir, 0700);
      if (res) {
         printf("Failed to chmod 0600 directory '%s': %s\n",
                dir, strerror(res));
         goto exit;
      }
   }
   bitc_check_create_file(cfgPath, "config");
   bitc_check_create_file(txPath, "tx-labels");

   if (!file_exists(ctcPath)) {
      struct config *cfg;

      bitc_check_create_file(ctcPath, "contacts");

      cfg = config_create();
      config_setstring(cfg, "1PBP4S44b1ro3kD6LQhBYnsF3fAp1HYPf2", "contact0.addr");
      config_setstring(cfg, "Support bitc development -- https://bit-c.github.com",
                       "contact0.label");

      config_setstring(cfg, "1PC9aZC4hNX2rmmrt7uHTfYAS3hRbph4UN", "contact1.addr");
      config_setstring(cfg, "Free Software Foundation -- https://fsf.org/donate/",
                       "contact1.label");
      config_setstring(cfg, "1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW", "contact2.addr");
      config_setstring(cfg, "Bitcoin Foundation -- https://bitcoinfoundation.org/donate",
                       "contact2.label");

      config_setstring(cfg, "3", "contacts.numEntries");

      res = config_write(cfg, ctcPath);
      if (res) {
         printf("Failed to save contacts file: %s\n", strerror(res));
      }
   }

exit:
   free(txPath);
   free(cfgPath);
   free(ctcPath);
   free(dir);

   return res;
}

/*
 *----------------------------------------------------------------
 *
 * bitc_load_misc_config --
 *
 *----------------------------------------------------------------
 */

static void
bitc_load_misc_config(void)
{
   char *defaultPath;
   char *dir;
   char *path;
   int res;

   btc->resolve_peers = config_getbool(btc->config, 1, "resolve.peers");

   dir = bitc_get_directory();

   /*
    * contacts.
    */
   defaultPath = safe_asprintf("%s/contacts.cfg", dir);
   path = config_getstring(btc->config, defaultPath, "contacts.filename");
   res = config_load(path, &btc->contactsCfg);
   if (res) {
      Warning("Please create a minimal config: %s\n", path);
   }
   free(defaultPath);
   free(path);

   /*
    * tx-label.
    */
   defaultPath = safe_asprintf("%s/tx-labels.cfg", dir);
   path = config_getstring(btc->config, defaultPath, "tx-labels.filename");
   res = config_load(path, &btc->txLabelsCfg);
   if (res) {
      Warning("Please create a minimal config: %s\n", path);
   }
   free(defaultPath);
   free(path);

   free(dir);
}

/*
 *---------------------------------------------------------------------
 *
 * bitc_openssl_init --
 *
 *---------------------------------------------------------------------
 */

static void
bitc_openssl_init(void)
{
   const char *sslVersion = SSLeay_version(SSLEAY_VERSION);
   int i;

   Log(LGPFX" using %s -- %u locks\n", sslVersion, CRYPTO_num_locks());

   SSL_library_init();
   ssl_mutex_array = OPENSSL_malloc(CRYPTO_num_locks() *
                                    sizeof *ssl_mutex_array);
   ASSERT(ssl_mutex_array);

   for (i = 0; i < CRYPTO_num_locks(); i++ ){
      pthread_mutex_init(&ssl_mutex_array[i], NULL);
   }
   CRYPTO_set_id_callback(bitc_openssl_thread_id_fun);
   CRYPTO_set_locking_callback(bitc_openssl_lock_fun);
}


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
	struct secure_area *passphrase	= NULL;
	const int minPeersInit 		= 50;
	char *addr_label 			= NULL;
	char *errStr 				= NULL;
	char *configPath 			= NULL;
	char *testStr 				= NULL;
	int maxPeers 				= 5;
	bool updateAndExit 			= 0;
	bool zap 					= 0;
	bool withui 				= 1;
	bool encrypt 				= 0;
	bool getpassword 			= 0;
	int res 					= 0;
	int c;

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

	util_bumpcoresize();
	bitc_check_config();

	res = bitc_load_config(&btc->config, configPath);
	if (res != 0) {
	  return res;
	}

	bitc_load_misc_config();
	btc->lock = mutex_alloc();
	btc->pw = poolworker_create(10);
	ipinfo_init();
	bitc_openssl_init();

	res = bitc_init(passphrase, updateAndExit, maxPeers, minPeersInit, &errStr);
	if (res) {
	  goto exit;
	}

	bitc_daemon(updateAndExit, maxPeers);
}
