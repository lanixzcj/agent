#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/statvfs.h>


#include "filemonitor.h"
#include "file.h"
#include "metrics.h"
#include <string>
#include <crafter.h>
/* Needed for VLAN testing */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_vlan.h>
#include <linux/sockios.h>
#include "utlist.h"
#include "mon_value.h"
#include <iostream>
#define OSNAME "Linux"
#define OSNAME_LEN strlen(OSNAME)

#define JT unsigned long long

/* sanity check and range limit */
static double
sanityCheck(int line, char *file, const char *func, double v, double diff, double dt, JT a, JT b, JT c, JT d);

/* Use unsigned long long for stats on systems with strtoull */
#if HAVE_STRTOULL
typedef unsigned long long stat_t;
#define STAT_MAX ULLONG_MAX
#define PRI_STAT "llu"
#define strtostat(nptr, endptr, base) strtoull(nptr, endptr, base)
#else
typedef unsigned long stat_t;
#define STAT_MAX ULONG_MAX
#define PRI_STAT "lu"
#define strtostat(nptr, endptr, base) strtoul(nptr, endptr, base)
#endif
using namespace Crafter;
using namespace std;
/* /proc/net/dev hash table stuff */
typedef struct net_dev_stats net_dev_stats;
struct net_dev_stats {
    char *name;
    stat_t rpi;
    stat_t rpo;
    stat_t rbi;
    stat_t rbo;
    net_dev_stats *next;
};
#define NHASH 101
#define MULTIPLIER 31
static net_dev_stats *netstats[NHASH];

char *proc_cpuinfo = NULL;
char proc_sys_kernel_osrelease[MAX_G_STRING_SIZE];

#define SCALING_MAX_FREQ "/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq"
//#define MAC_ADDRESS "/sys/class/net/eth0/address"
char sys_devices_system_cpu[32];
char mac_address[24];
int cpufreq;

timely_file proc_stat = {{0, 0}, 1., "/proc/stat", NULL, BUFFSIZE};
timely_file proc_loadavg = {{0, 0}, 5., "/proc/loadavg", NULL, BUFFSIZE};
timely_file proc_meminfo = {{0, 0}, 5., "/proc/meminfo", NULL, BUFFSIZE};
timely_file proc_net_dev = {{0, 0}, 1., "/proc/net/dev", NULL, BUFFSIZE};
timely_file user_cmd_log = {{0, 0}, 5., "/var/log/usercmd.log", NULL, BUFFSIZE};

/*
 ** A helper function to determine the number of cpustates in /proc/stat (MKN)
 */
#define NUM_CPUSTATES_24X 4
#define NUM_CPUSTATES_26X 7
static unsigned int num_cpustates;

/*net sniffer*/
Sniffer *sniff;
/*net value*/
g_val_t net_val;
/* get netInterface*/
string getInterface()
{
    string iface ;
    /* Set the interface */
//    iface = "eth0";

    /*get interface*/

    char errbuf[100];
    iface =pcap_lookupdev(errbuf);
    return iface;
}
/* Function for handling a packet */
void PacketHandler(Packet* sniff_packet, void* user) {
    /* sniff_packet -> pointer to the packet captured */
    /* user -> void pointer to the data supplied by the user */
    /* Check if there is a payload */
    RawLayer* raw_payload = sniff_packet->GetLayer<RawLayer>();
    if(raw_payload) {
        net_val.hash = NULL;
        //get time
        char value[1024];
        hash_t *node = (hash_t*)malloc(sizeof(hash_t));
        // sprintf(value, "%ld", time(NULL));
        strcpy(node->key, "time");
        char *time_c = (char*)malloc(sizeof(15));
        sprintf(time_c,"%ld",time(NULL));
        node->data = time_c;
        HASH_ADD_STR(net_val.hash, key, node);

        cout<<"hehehehehehehehehe\n";
        /* Summarize Ethernet data */
        Ethernet* Ethernet_layer = sniff_packet->GetLayer<Ethernet>();
        if(Ethernet_layer)
        {
            node = (hash_t*)malloc(sizeof(hash_t));
            strcpy(node->key, "source_MAC");
            string *sMACp = new string;
            *sMACp = Ethernet_layer->GetSourceMAC();
            char *sMACcp= (char *) (*sMACp).data();
            cout<<"source mac address\n";
            cout<<sMACcp<<endl;
            cout<<"source mac address\n";
            node->data = sMACcp;
            HASH_ADD_STR(net_val.hash, key, node);

            node = (hash_t*)malloc(sizeof(hash_t));
            strcpy(node->key, "des_MAC");
            string *dMACp = new string;
            *dMACp = Ethernet_layer->GetDestinationMAC();
            char *dMACcp= (char *) (*dMACp).data();
            cout<<"des mac address\n";
            cout<<dMACcp<<endl;
            cout<<"des mac address\n";
            node->data = dMACcp;
            HASH_ADD_STR(net_val.hash, key, node);
        }

        /* Summarize IP data */
        IP* IP_layer = sniff_packet->GetLayer<IP>();
        if(IP_layer)
        {
            node = (hash_t*)malloc(sizeof(hash_t));
            strcpy(node->key, "source_IP");
            string *sIPp = new string;
            *sIPp = IP_layer->GetSourceIP();
            char *sIPcp= (char *) (*sIPp).data();
            cout<<"s IP\n";
            cout<<*sIPp<<endl;
            cout<<"s IP\n";
            node->data = sIPcp;
            HASH_ADD_STR(net_val.hash, key, node);

            node = (hash_t*)malloc(sizeof(hash_t));
            strcpy(node->key, "des_IP");
            string *dIPp = new string;
            *dIPp = IP_layer->GetDestinationIP();
            char *dIPcp= (char *) (*dIPp).data();
            cout<<"d IP\n";
            cout<<*dIPp<<endl;
            cout<<"d IP\n";
            node->data = dIPcp;
            HASH_ADD_STR(net_val.hash, key, node);
        }

        /* Summarize TCP data */
        TCP* tcp_layer = sniff_packet->GetLayer<TCP>();
        if(tcp_layer)
        {
            node = (hash_t*)malloc(sizeof(hash_t));
            strcpy(node->key, "source_port");
            short unsigned int *sTCPp = new short unsigned int;
            *sTCPp = tcp_layer->GetSrcPort();
            char *sTCPcp = (char*)malloc(sizeof(char)*6);
            snprintf(sTCPcp, sizeof(sTCPcp), "%d", *sTCPp);
            cout<<"s TCP port\n";
            cout<<sTCPcp<<endl;
            cout<<"s TCP port\n";
            node->data = sTCPcp;
            HASH_ADD_STR(net_val.hash, key, node);

            node = (hash_t*)malloc(sizeof(hash_t));
            strcpy(node->key, "des_port");
            short unsigned int *dTCPp = new short unsigned int;
            *dTCPp = tcp_layer->GetDstPort();
            char *dTCPcp = (char*)malloc(sizeof(char)*6);
            snprintf(dTCPcp, sizeof(dTCPcp), "%d", *dTCPp);
            cout<<"d TCP port\n";
            cout<<dTCPcp<<endl;
            cout<<"d TCP port\n";
            node->data = dTCPcp;
            HASH_ADD_STR(net_val.hash, key, node);
        }

        /* Summarize UDP data */
        UDP* UDP_layer = sniff_packet->GetLayer<UDP>();
        if(UDP_layer)
        {
            node = (hash_t*)malloc(sizeof(hash_t));
            strcpy(node->key, "source_port");
            short unsigned int *sUCPp = new short unsigned int;
            *sUCPp = UDP_layer->GetSrcPort();
            char *sUDPcp = (char*)malloc(sizeof(char)*6);
            snprintf(sUDPcp, sizeof(sUDPcp), "%d", *sUCPp);
            cout<<"s UDP port\n";
            cout<<sUDPcp<<endl;
            cout<<"s UDP port\n";
            node->data = sUDPcp;
            HASH_ADD_STR(net_val.hash, key, node);

            node = (hash_t*)malloc(sizeof(hash_t));
            strcpy(node->key, "des_port");
            short unsigned int *dUCPp = new short unsigned int;
            *dUCPp = UDP_layer->GetDstPort();
            char *dUDPcp = (char*)malloc(sizeof(char)*6);
            snprintf(dUDPcp, sizeof(dUDPcp), "%d", *dUCPp);
            cout<<"d UDP port\n";
            cout<<dUDPcp<<endl;
            cout<<"d UDP port\n";
            node->data = dUDPcp;
            HASH_ADD_STR(net_val.hash, key, node);
        }
    }
}


unsigned int num_cpustates_func(void)
{
    char *p;
    unsigned int i = 0;

    proc_stat.last_read.tv_sec = 0;
    proc_stat.last_read.tv_usec = 0;
    p = update_file(&proc_stat);
    proc_stat.last_read.tv_sec = 0;
    proc_stat.last_read.tv_usec = 0;

    /*
     ** Skip initial "cpu" token
     */
    p = skip_token(p);
    p = skip_whitespace(p);
    /*
     ** Loop over file until next "cpu" token is found.
     ** i=4 : Linux 2.4.x
     ** i=7 : Linux 2.6.x
     ** i=8 : Linux 2.6.11
     */
    while (strncmp(p, "cpu", 3)) {
        p = skip_token(p);
        p = skip_whitespace(p);
        i++;
    }

    return i;
}

/*
 ** Helper functions to hash /proc/net/dev stats (Kernighan & Pike)
 */
static unsigned int hashval(const char *s)
{
    unsigned int hval;
    unsigned char *p;

    hval = 0;
    for (p = (unsigned char *) s; *p != '\0'; p++)
        hval = MULTIPLIER * hval + *p;
    return hval % NHASH;
}

static net_dev_stats *hash_lookup(char *devname, size_t nlen)
{
    int hval;
    net_dev_stats *stats;
    char *name = strndup(devname, nlen);

    hval = hashval(name);
    for (stats = netstats[hval]; stats != NULL; stats = stats->next) {
        if (strcmp(name, stats->name) == 0) {
            free(name);
            return stats;
        }
    }

    stats = (net_dev_stats *) malloc(sizeof(net_dev_stats));
    if (stats == NULL) {
        err_msg("unable to allocate memory for /proc/net/dev/stats in hash_lookup(%s,%zd)", name, nlen);
        free(name);
        return NULL;
    }
    stats->name = strndup(devname, nlen);
    stats->rpi = 0;
    stats->rpo = 0;
    stats->rbi = 0;
    stats->rbo = 0;
    stats->next = netstats[hval];
    netstats[hval] = stats;

    free(name);
    return stats;
}


/*
 ** Helper functions for vlan interface testing
 */
static int is_vlan_iface(char *if_name)
{
    int fd, rc;
    struct vlan_ioctl_args vlan_args;

    fd = socket(PF_INET, SOCK_DGRAM, 0);

    // fail if can't open the socket
    if (fd < 0) {
        return 0;
    };

    /*   vlan_args.cmd = GET_VLAN_VID_CMD;*/
    strncpy(vlan_args.device1, if_name, sizeof(vlan_args.device1));
    rc = ioctl(fd, SIOCGIFVLAN, &vlan_args);

    close(fd);
    if (rc < 0) {
        return 0; // false
    } else {
        return 1; // vlan iface indeed
    }

};


/*
 * FIXME: this routine should be rewritten to do per-interface statistics
 */
static double bytes_in = 0, bytes_out = 0, pkts_in = 0, pkts_out = 0;

void update_ifdata(char *caller)
{
    char *p;
    int i;
    static struct timeval stamp = {0, 0};
    stat_t rbi = 0, rbo = 0, rpi = 0, rpo = 0;
    stat_t l_bytes_in = 0, l_bytes_out = 0, l_pkts_in = 0, l_pkts_out = 0;
    double l_bin, l_bout, l_pin, l_pout;
    net_dev_stats *ns;
    float t;

    p = update_file(&proc_net_dev);
    if ((proc_net_dev.last_read.tv_sec != stamp.tv_sec) &&
        (proc_net_dev.last_read.tv_usec != stamp.tv_usec)) {
        /*  skip past the two-line header ... */
        p = index(p, '\n') + 1;
        p = index(p, '\n') + 1;

        while (*p != 0x00) {
            /*  skip past the interface tag portion of this line */
            /*  but save the name of the interface (hash key) */
            char *src;
            size_t n = 0;

            char if_name[IFNAMSIZ];
            int vlan = 0; // vlan flag

            while (p != 0x00 && isblank(*p))
                p++;

            src = p;
            while (p != 0x00 && *p != ':') {
                n++;
                p++;
            }

            p = index(p, ':');
            /* l.flis: check whether iface is vlan */
            if (p && n < IFNAMSIZ) {
                strncpy(if_name, src, IFNAMSIZ);
                if_name[n] = '\0';
                vlan = is_vlan_iface(if_name);
            };

            /* Ignore 'lo' and 'bond*' interfaces (but sanely) */
            /* l.flis: skip vlan interfaces to avoid double counting*/
            if (p && strncmp(src, "lo", 2) &&
                strncmp(src, "bond", 4) && !vlan) {
                p++;
                /* Check for data from the last read for this */
                /* interface.  If nothing exists, add to the table. */
                ns = hash_lookup(src, n);
                if (!ns) return;

                /* receive */
                rbi = strtostat(p, &p, 10);
                if (rbi >= ns->rbi) {
                    l_bytes_in += rbi - ns->rbi;
                } else {
                    debug_msg("update_ifdata(%s) - Overflow in rbi: %"PRI_STAT" -> %"PRI_STAT, caller, ns->rbi, rbi);
                    l_bytes_in += STAT_MAX - ns->rbi + rbi;
                }
                ns->rbi = rbi;

                rpi = strtostat(p, &p, 10);
                if (rpi >= ns->rpi) {
                    l_pkts_in += rpi - ns->rpi;
                } else {
                    debug_msg("updata_ifdata(%s) - Overflow in rpi: %"PRI_STAT" -> %"PRI_STAT, caller, ns->rpi, rpi);
                    l_pkts_in += STAT_MAX - ns->rpi + rpi;
                }
                ns->rpi = rpi;

                /* skip unneeded metrics */
                for (i = 0; i < 6; i++) rbo = strtostat(p, &p, 10);

                /* transmit */
                rbo = strtostat(p, &p, 10);
                if (rbo >= ns->rbo) {
                    l_bytes_out += rbo - ns->rbo;
                } else {
                    debug_msg("update_ifdata(%s) - Overflow in rbo: %"PRI_STAT" -> %"PRI_STAT, caller, ns->rbo, rbo);
                    l_bytes_out += STAT_MAX - ns->rbo + rbo;
                }
                ns->rbo = rbo;

                rpo = strtostat(p, &p, 10);
                if (rpo >= ns->rpo) {
                    l_pkts_out += rpo - ns->rpo;
                } else {
                    debug_msg("update_ifdata(%s) - Overflow in rpo: %"PRI_STAT" -> %"PRI_STAT, caller, ns->rpo, rpo);
                    l_pkts_out += STAT_MAX - ns->rpo + rpo;
                }
                ns->rpo = rpo;
            }
            p = index(p, '\n') + 1;
        }

        /*
         * Compute timediff. Check for bogus delta-t
         */
        t = timediff(&proc_net_dev.last_read, &stamp);
        if (t < proc_net_dev.thresh) {
            err_msg("update_ifdata(%s) - Dubious delta-t: %f", caller, t);
            return;
        }
        stamp = proc_net_dev.last_read;

        /*
         * Compute rates in local variables
         */
        l_bin = l_bytes_in / t;
        l_bout = l_bytes_out / t;
        l_pin = l_pkts_in / t;
        l_pout = l_pkts_out / t;

        /*
         * Check for "invalid" data, caused by HW error. Throw away dubious data points
         * FIXME: This should be done per-interface, with threshholds depending on actual link speed
         */
        if ((l_bin > 1.0e13) || (l_bout > 1.0e13) ||
            (l_pin > 1.0e8) || (l_pout > 1.0e8)) {
            err_msg("update_ifdata(%s): %g %g %g %g / %g", caller,
                    l_bin, l_bout, l_pin, l_pout, t);
            return;
        }

        /*
         * Finally return Values
         */
        bytes_in = l_bin;
        bytes_out = l_bout;
        pkts_in = l_pin;
        pkts_out = l_pout;
    }

    return;
}

/*
 * This function is called only once by the gmond.  Use to
 * initialize data structures, etc or just return SYNAPSE_SUCCESS;
 */
g_val_t metric_init(void)
{
    g_val_t rval;
    char *dummy;
    struct stat struct_stat;

    num_cpustates = num_cpustates_func();

    /* scaling_max_freq will contain the max CPU speed if available */
    cpufreq = 0;
    if (stat(SCALING_MAX_FREQ, &struct_stat) == 0) {
        cpufreq = 1;
        dummy = sys_devices_system_cpu;
        slurpfile(SCALING_MAX_FREQ, &dummy, 32);
    }
    std::string temps = "/sys/class/net/";
    std::string *sMAC_ADDRESS = new std::string;
    *sMAC_ADDRESS += temps;
    while(getInterface() == "any")
    {
        sleep(10);
    }
    std::string net_interface = getInterface();

    std::cout<<"net_interface"<<std::endl;
    std::cout<<net_interface<<std::endl;
    std::cout<<"net_interface"<<std::endl;
    sniff = new Sniffer("ip host !192.168.3.134",net_interface,PacketHandler);
    *sMAC_ADDRESS += net_interface;
    temps = "/address";
    *sMAC_ADDRESS += temps;
    char* MAC_ADDRESS = (char *)(*sMAC_ADDRESS).data();

    if (stat(MAC_ADDRESS, &struct_stat) == 0) {
        dummy = mac_address;
        slurpfile(MAC_ADDRESS, &dummy, 24);
        std::cout<<"mac_address"<<std::endl;
        std::cout<<mac_address<<std::endl;
        std::cout<<"mac_address"<<std::endl;
    }

    dummy = proc_cpuinfo;
    rval.int32 = slurpfile("/proc/cpuinfo", &dummy, BUFFSIZE);
    if (proc_cpuinfo == NULL)
        proc_cpuinfo = dummy;

    if (rval.int32 == SLURP_FAILURE) {
        err_msg("metric_init() got an error from slurpfile() /proc/cpuinfo");
        rval.int32 = SYNAPSE_FAILURE;
        return rval;
    }

    dummy = proc_sys_kernel_osrelease;
    rval.int32 = slurpfile("/proc/sys/kernel/osrelease", &dummy,
                           MAX_G_STRING_SIZE);
    if (rval.int32 == SLURP_FAILURE) {
        err_msg("metric_init() got an error from slurpfile()");
        rval.int32 = SYNAPSE_FAILURE;
        return rval;
    }

    /* Get rid of pesky \n in osrelease */
    proc_sys_kernel_osrelease[rval.int32 - 1] = '\0';

    dummy = update_file(&proc_net_dev);
    if (dummy == NULL) {
        err_msg("metric_init() got an error from update_file()");
        rval.int32 = SYNAPSE_FAILURE;
        return rval;
    }

    update_ifdata("metric_inint");

    rval.int32 = SYNAPSE_SUCCESS;
    return rval;
}

g_val_t pkts_in_func(void)
{
    g_val_t val;

    update_ifdata("PI");
    val.f = pkts_in;
    debug_msg(" ********** pkts_in:  %f", pkts_in);
    return val;
}

g_val_t pkts_out_func(void)
{
    g_val_t val;

    update_ifdata("PO");
    val.f = pkts_out;
    debug_msg(" ********** pkts_out:  %f", pkts_out);
    return val;
}

g_val_t bytes_out_func(void)
{
    g_val_t val;

    update_ifdata("BO");
    val.f = bytes_out;
    debug_msg(" ********** bytes_out:  %f", bytes_out);
    return val;
}

g_val_t bytes_in_func(void)
{
    g_val_t val;

    update_ifdata("BI");
    val.f = bytes_in;
    debug_msg(" ********** bytes_in:  %f", bytes_in);
    return val;
}

g_val_t cpu_num_func(void)
{
    g_val_t val;

    /* Use _SC_NPROCESSORS_ONLN to get operating cpus */
    val.uint16 = get_nprocs();

    return val;
}

g_val_t cpu_speed_func(void)
{
    char *p;
    static g_val_t val = {0};

    /* we'll use scaling_max_freq before we fallback on proc_cpuinfo */
    if (cpufreq && !val.uint32) {
        p = sys_devices_system_cpu;
        val.uint32 = (uint32_t) (strtol(p, (char **) NULL, 10) / 1000);
    }

    /* i386, ia64, x86_64 and hppa all report MHz in the same format */
#if defined (__i386__) || defined(__ia64__) || defined(__hppa__) || defined(__x86_64__)
    if (!val.uint32) {
        p = proc_cpuinfo;
        p = strstr(p, "cpu MHz");
        if (p) {
            p = strchr(p, ':');
            p++;
            p = skip_whitespace(p);
            val.uint32 = (uint32_t) strtol(p, (char **) NULL, 10);
        } else {
            val.uint32 = 0;
        }
    }
#endif
#if defined (__alpha__)
    if (! val.uint32 ) {
        int num;
        p = proc_cpuinfo;
        p = strstr( p, "cycle frequency [Hz]" );
        if (p) {
            p = strchr( p, ':' );
            p++;
            p = skip_whitespace(p);
            sscanf(p, "%d", &num);
            num = num / 1000000;  /* Convert to Mhz */
            val.uint32 = (uint32_t)num;
        } else {
            val.uint32 = 0;
        }
    }
#endif
#if defined (__powerpc__)
    if (! val.uint32 )
    {
        p = proc_cpuinfo;
        p = strstr( p, "clock" );
        if (p) {
            p = strchr( p, ':' );
            p++;
            p = skip_whitespace(p);
            val.uint32 = (uint32_t)strtol( p, (char **)NULL , 10 );
        } else {
            val.uint32 = 0;
        }
    }
#endif
    return val;
}

/*
 ** FIXME: all functions using /proc/meminfo sould use a central routine like networking
 */
g_val_t mem_total_func(void)
{
    char *p;
    g_val_t val;

    p = strstr(update_file(&proc_meminfo), "MemTotal:");
    if (p) {
        p = skip_token(p);
        val.f = atof(p);
    } else {
        val.f = 0;
    }

    return val;
}

g_val_t swap_total_func(void)
{
    char *p;
    g_val_t val;

    p = strstr(update_file(&proc_meminfo), "SwapTotal:");
    if (p) {
        p = skip_token(p);
        val.f = atof(p);
    } else {
        val.f = 0;
    }

    return val;
}

g_val_t boottime_func(void)
{
    char *p;
    g_val_t val;

    p = update_file(&proc_stat);

    p = strstr(p, "btime");
    if (p) {
        p = skip_token(p);
        val.uint32 = atoi(p);
    } else {
        val.uint32 = 0;
    }

    return val;
}

g_val_t sys_clock_func(void)
{
    g_val_t val;

    val.uint32 = time(NULL);

    return val;
}

g_val_t machine_type_func(void)
{
    g_val_t val;

#ifdef __i386__
    snprintf(val.str, MAX_G_STRING_SIZE, "x86");
#endif
#ifdef __x86_64__
    snprintf(val.str, MAX_G_STRING_SIZE, "x86_64");
#endif
#ifdef __ia64__
    snprintf(val.str, MAX_G_STRING_SIZE, "ia64");
#endif
#ifdef __sparc__
    snprintf(val.str, MAX_G_STRING_SIZE, "sparc");
#endif
#ifdef __alpha__
    snprintf(val.str, MAX_G_STRING_SIZE, "alpha");
#endif
#ifdef __powerpc__
    snprintf(val.str, MAX_G_STRING_SIZE, "powerpc");
#endif
#ifdef __m68k__
    snprintf(val.str, MAX_G_STRING_SIZE, "m68k");
#endif
#ifdef __mips__
    snprintf(val.str, MAX_G_STRING_SIZE, "mips");
#endif
#ifdef __arm__
    snprintf(val.str, MAX_G_STRING_SIZE, "arm");
#endif
#ifdef __hppa__
    snprintf(val.str, MAX_G_STRING_SIZE, "hppa");
#endif
#ifdef __s390__
    snprintf(val.str, MAX_G_STRING_SIZE, "s390");
#endif

    return val;
}

g_val_t os_name_func(void)
{
    g_val_t val;

    snprintf(val.str, MAX_G_STRING_SIZE, "Linux");

    return val;
}

g_val_t os_release_func(void)
{
    g_val_t val;

    snprintf(val.str, MAX_G_STRING_SIZE, "%s", proc_sys_kernel_osrelease);

    return val;
}

/*
 * FIXME: all functions using /proc/stat should be rewritten to use a
 * central function like networking
 */

/*
 * A helper function to return the total number of cpu jiffies
 */
JT total_jiffies_func(void)
{
    char *p;
    JT user_jiffies, nice_jiffies, system_jiffies, idle_jiffies,
            wio_jiffies, irq_jiffies, sirq_jiffies, steal_jiffies;

    p = update_file(&proc_stat);
    p = skip_token(p);
    p = skip_whitespace(p);
    user_jiffies = strtod(p, &p);
    p = skip_whitespace(p);
    nice_jiffies = strtod(p, &p);
    p = skip_whitespace(p);
    system_jiffies = strtod(p, &p);
    p = skip_whitespace(p);
    idle_jiffies = strtod(p, &p);

    if (num_cpustates == NUM_CPUSTATES_24X)
        return user_jiffies + nice_jiffies + system_jiffies + idle_jiffies;

    p = skip_whitespace(p);
    wio_jiffies = strtod(p, &p);
    p = skip_whitespace(p);
    irq_jiffies = strtod(p, &p);
    p = skip_whitespace(p);
    sirq_jiffies = strtod(p, &p);

    if (num_cpustates == NUM_CPUSTATES_26X)
        return user_jiffies + nice_jiffies + system_jiffies + idle_jiffies +
               wio_jiffies + irq_jiffies + sirq_jiffies;

    p = skip_whitespace(p);
    steal_jiffies = strtod(p, &p);

    return user_jiffies + nice_jiffies + system_jiffies + idle_jiffies +
           wio_jiffies + irq_jiffies + sirq_jiffies + steal_jiffies;
}

double sanityCheck(int line, char *file, const char *func, double v, double diff, double dt, JT a, JT b, JT c, JT d)
{
    if (v > 100.0) {
        err_msg("file %s, line %d, fn %s: val > 100: %g ~ %g / %g = (%llu - %llu) / (%llu - %llu)\n", file, line, func,
                v, diff, dt, a, b, c, d);
        return 100.0;
    } else if (v < 0.0) {
        err_msg("file %s, line %d, fn %s: val < 0: %g ~ %g / %g = (%llu - %llu) / (%llu - %llu)\n", file, line, func, v,
                diff, dt, a, b, c, d);
        return 0.0;
    }
    return v;
}

g_val_t cpu_user_func(void)
{
    char *p;
    static g_val_t val;
    static struct timeval stamp = {0, 0};
    static JT last_user_jiffies, user_jiffies,
            last_total_jiffies, total_jiffies, diff;

    p = update_file(&proc_stat);
    if ((proc_stat.last_read.tv_sec != stamp.tv_sec) &&
        (proc_stat.last_read.tv_usec != stamp.tv_usec)) {
        stamp = proc_stat.last_read;

        p = skip_token(p);
        user_jiffies = strtod(p, (char **) NULL);
        total_jiffies = total_jiffies_func();

        diff = user_jiffies - last_user_jiffies;

        if (diff)
            val.f = ((double) diff / (double) (total_jiffies - last_total_jiffies)) * 100.0;
        else
            val.f = 0.0;

        val.f = sanityCheck(__LINE__, __FILE__, __FUNCTION__, val.f, (double) diff,
                            (double) (total_jiffies - last_total_jiffies), user_jiffies, last_user_jiffies,
                            total_jiffies, last_total_jiffies);

        last_user_jiffies = user_jiffies;
        last_total_jiffies = total_jiffies;

    }
    return val;
}

g_val_t cpu_nice_func(void)
{
    char *p;
    static g_val_t val;
    static struct timeval stamp = {0, 0};
    static JT last_nice_jiffies, nice_jiffies,
            last_total_jiffies, total_jiffies, diff;

    p = update_file(&proc_stat);
    if ((proc_stat.last_read.tv_sec != stamp.tv_sec) &&
        (proc_stat.last_read.tv_usec != stamp.tv_usec)) {
        stamp = proc_stat.last_read;

        p = skip_token(p);
        p = skip_token(p);
        nice_jiffies = strtod(p, (char **) NULL);
        total_jiffies = total_jiffies_func();

        diff = (nice_jiffies - last_nice_jiffies);

        if (diff)
            val.f = ((double) diff / (double) (total_jiffies - last_total_jiffies)) * 100.0;
        else
            val.f = 0.0;

        val.f = sanityCheck(__LINE__, __FILE__, __FUNCTION__, val.f, (double) diff,
                            (double) (total_jiffies - last_total_jiffies), nice_jiffies, last_nice_jiffies,
                            total_jiffies, last_total_jiffies);

        last_nice_jiffies = nice_jiffies;
        last_total_jiffies = total_jiffies;

    }
    return val;
}

g_val_t cpu_system_func(void)
{
    char *p;
    static g_val_t val;
    static struct timeval stamp = {0, 0};
    static JT last_system_jiffies, system_jiffies,
            last_total_jiffies, total_jiffies, diff;

    p = update_file(&proc_stat);
    if ((proc_stat.last_read.tv_sec != stamp.tv_sec) &&
        (proc_stat.last_read.tv_usec != stamp.tv_usec)) {
        stamp = proc_stat.last_read;

        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        system_jiffies = strtod(p, (char **) NULL);
        if (num_cpustates > NUM_CPUSTATES_24X) {
            p = skip_token(p);
            p = skip_token(p);
            p = skip_token(p);
            system_jiffies += strtod(p, (char **) NULL); /* "intr" counted in system */
            p = skip_token(p);
            system_jiffies += strtod(p, (char **) NULL); /* "sintr" counted in system */
        }
        total_jiffies = total_jiffies_func();

        diff = system_jiffies - last_system_jiffies;

        if (diff)
            val.f = ((double) diff / (double) (total_jiffies - last_total_jiffies)) * 100.0;
        else
            val.f = 0.0;

        val.f = sanityCheck(__LINE__, __FILE__, __FUNCTION__, val.f, (double) diff,
                            (double) (total_jiffies - last_total_jiffies), system_jiffies, last_system_jiffies,
                            total_jiffies, last_total_jiffies);

        last_system_jiffies = system_jiffies;
        last_total_jiffies = total_jiffies;

    }
    return val;
}

g_val_t cpu_idle_func(void)
{
    char *p;
    static g_val_t val;
    static struct timeval stamp = {0, 0};
    static JT last_idle_jiffies, idle_jiffies,
            last_total_jiffies, total_jiffies, diff;

    p = update_file(&proc_stat);
    if ((proc_stat.last_read.tv_sec != stamp.tv_sec) &&
        (proc_stat.last_read.tv_usec != stamp.tv_usec)) {
        stamp = proc_stat.last_read;

        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        idle_jiffies = strtod(p, (char **) NULL);
        total_jiffies = total_jiffies_func();

        diff = idle_jiffies - last_idle_jiffies;

        if (diff)
            val.f = ((double) diff / (double) (total_jiffies - last_total_jiffies)) * 100.0;
        else
            val.f = 0.0;

        val.f = sanityCheck(__LINE__, __FILE__, __FUNCTION__, val.f, (double) diff,
                            (double) (total_jiffies - last_total_jiffies), idle_jiffies, last_idle_jiffies,
                            total_jiffies, last_total_jiffies);

        last_idle_jiffies = idle_jiffies;
        last_total_jiffies = total_jiffies;

    }

    return val;
}

g_val_t cpu_aidle_func(void)
{
    char *p;
    g_val_t val;
    JT idle_jiffies, total_jiffies;

    p = update_file(&proc_stat);

    p = skip_token(p);
    p = skip_token(p);
    p = skip_token(p);
    p = skip_token(p);
    idle_jiffies = (JT) strtod(p, (char **) NULL);
    total_jiffies = total_jiffies_func();

    val.f = ((double) idle_jiffies / (double) total_jiffies) * 100.0;

    val.f = sanityCheck(__LINE__, __FILE__, __FUNCTION__, val.f, (double) idle_jiffies, (double) total_jiffies,
                        idle_jiffies, total_jiffies, 0, 0);
    return val;
}

g_val_t cpu_wio_func(void)
{
    char *p;
    static g_val_t val;
    static struct timeval stamp = {0, 0};
    static JT last_wio_jiffies, wio_jiffies,
            last_total_jiffies, total_jiffies, diff;

    if (num_cpustates == NUM_CPUSTATES_24X) {
        val.f = 0.0;
        return val;
    }

    p = update_file(&proc_stat);
    if ((proc_stat.last_read.tv_sec != stamp.tv_sec) &&
        (proc_stat.last_read.tv_usec != stamp.tv_usec)) {
        stamp = proc_stat.last_read;

        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        wio_jiffies = strtod(p, (char **) NULL);
        total_jiffies = total_jiffies_func();

        diff = wio_jiffies - last_wio_jiffies;

        if (diff)
            val.f = ((double) diff / (double) (total_jiffies - last_total_jiffies)) * 100.0;
        else
            val.f = 0.0;

        val.f = sanityCheck(__LINE__, __FILE__, __FUNCTION__, val.f, (double) diff,
                            (double) (total_jiffies - last_total_jiffies), wio_jiffies, last_wio_jiffies, total_jiffies,
                            last_total_jiffies);

        last_wio_jiffies = wio_jiffies;
        last_total_jiffies = total_jiffies;

    }

    return val;
}

g_val_t cpu_intr_func(void)
{
    char *p;
    static g_val_t val;
    static struct timeval stamp = {0, 0};
    static JT last_intr_jiffies, intr_jiffies,
            last_total_jiffies, total_jiffies, diff;

    if (num_cpustates == NUM_CPUSTATES_24X) {
        val.f = 0.;
        return val;
    }

    p = update_file(&proc_stat);
    if ((proc_stat.last_read.tv_sec != stamp.tv_sec) &&
        (proc_stat.last_read.tv_usec != stamp.tv_usec)) {
        stamp = proc_stat.last_read;

        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        intr_jiffies = strtod(p, (char **) NULL);
        total_jiffies = total_jiffies_func();

        diff = intr_jiffies - last_intr_jiffies;

        if (diff)
            val.f = ((double) diff / (double) (total_jiffies - last_total_jiffies)) * 100.0;
        else
            val.f = 0.0;

        val.f = sanityCheck(__LINE__, __FILE__, __FUNCTION__, val.f, (double) diff,
                            (double) (total_jiffies - last_total_jiffies), intr_jiffies, last_intr_jiffies,
                            total_jiffies, last_total_jiffies);

        last_intr_jiffies = intr_jiffies;
        last_total_jiffies = total_jiffies;

    }

    return val;
}

g_val_t cpu_sintr_func(void)
{
    char *p;
    static g_val_t val;
    static struct timeval stamp = {0, 0};
    static JT last_sintr_jiffies, sintr_jiffies,
            last_total_jiffies, total_jiffies, diff;

    if (num_cpustates == NUM_CPUSTATES_24X) {
        val.f = 0.;
        return val;
    }

    p = update_file(&proc_stat);
    if ((proc_stat.last_read.tv_sec != stamp.tv_sec) &&
        (proc_stat.last_read.tv_usec != stamp.tv_usec)) {
        stamp = proc_stat.last_read;

        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        sintr_jiffies = strtod(p, (char **) NULL);
        total_jiffies = total_jiffies_func();

        diff = sintr_jiffies - last_sintr_jiffies;

        if (diff)
            val.f = ((double) diff / (double) (total_jiffies - last_total_jiffies)) * 100.0;
        else
            val.f = 0.0;

        val.f = sanityCheck(__LINE__, __FILE__, __FUNCTION__, val.f, (double) diff,
                            (double) (total_jiffies - last_total_jiffies), sintr_jiffies, last_sintr_jiffies,
                            total_jiffies, last_total_jiffies);

        last_sintr_jiffies = sintr_jiffies;
        last_total_jiffies = total_jiffies;

    }

    return val;
}

g_val_t cpu_steal_func(void)
{
    char *p;
    static g_val_t val;
    static struct timeval stamp = {0, 0};
    static double last_steal_jiffies, steal_jiffies,
            last_total_jiffies, total_jiffies, diff;

    p = update_file(&proc_stat);
    if ((proc_stat.last_read.tv_sec != stamp.tv_sec) &&
        (proc_stat.last_read.tv_usec != stamp.tv_usec)) {
        stamp = proc_stat.last_read;

        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        p = skip_token(p);
        steal_jiffies = strtod(p, (char **) NULL);
        total_jiffies = total_jiffies_func();

        diff = steal_jiffies - last_steal_jiffies;

        if (diff)
            val.f = (diff / (total_jiffies - last_total_jiffies)) * 100;
        else
            val.f = 0.0;

        last_steal_jiffies = steal_jiffies;
        last_total_jiffies = total_jiffies;

    }

    return val;
}

g_val_t load_one_func(void)
{
    g_val_t val;

    val.f = strtod(update_file(&proc_loadavg), (char **) NULL);

    return val;
}

g_val_t load_five_func(void)
{
    char *p;
    g_val_t val;

    p = update_file(&proc_loadavg);
    p = skip_token(p);
    val.f = strtod(p, (char **) NULL);

    return val;
}

g_val_t load_fifteen_func(void)
{
    char *p;
    g_val_t val;

    p = update_file(&proc_loadavg);

    p = skip_token(p);
    p = skip_token(p);
    val.f = strtod(p, (char **) NULL);

    return val;
}

g_val_t proc_run_func(void)
{
    char *p;
    g_val_t val;

    p = update_file(&proc_loadavg);
    p = skip_token(p);
    p = skip_token(p);
    p = skip_token(p);
    val.uint32 = strtol(p, (char **) NULL, 10);

    val.uint32--;
    /* This shouldn't happen.. but it might */
    if (val.uint32 < 0)
        val.uint32 = 0;

    return val;
}

g_val_t proc_total_func(void)
{
    char *p;
    g_val_t val;

    p = update_file(&proc_loadavg);
    p = skip_token(p);
    p = skip_token(p);
    p = skip_token(p);
    p = skip_whitespace(p);
    while (isdigit(*p))
        p++;
    p++;  /* skip the slash-/ */
    val.uint32 = strtol(p, (char **) NULL, 10);

    return val;
}

g_val_t mem_free_func(void)
{
    char *p;
    g_val_t val;

    p = strstr(update_file(&proc_meminfo), "MemFree:");
    if (p) {
        p = skip_token(p);
        val.f = atof(p);
    } else {
        val.f = 0.0;
    }

    return val;
}

g_val_t mem_shared_func(void)
{
    char *p;
    g_val_t val;

    /*
     ** Broken since linux-2.5.52 when Memshared was removed !!
     */
    p = strstr(update_file(&proc_meminfo), "MemShared:");
    if (p) {
        p = skip_token(p);
        val.f = atof(p);
    } else {
        val.f = 0.0;
    }

    return val;
}

g_val_t mem_buffers_func(void)
{
    char *p;
    g_val_t val;

    p = strstr(update_file(&proc_meminfo), "Buffers:");
    if (p) {
        p = skip_token(p);
        val.f = atof(p);
    } else {
        val.f = 0.0;
    }

    return val;
}

g_val_t mem_sreclaimable_func(void)
{
    char *p;
    g_val_t val;

    p = strstr(update_file(&proc_meminfo), "SReclaimable:");
    if (p) {
        p = skip_token(p);
        val.f = atof(p);
    } else {
        val.f = 0;
    }

    return val;
}

g_val_t mem_cached_func(void)
{
    char *p;
    g_val_t val;

    p = strstr(update_file(&proc_meminfo), "Cached:");
    if (p) {
        p = skip_token(p);
        val.f = atof(p);
    } else {
        val.f = 0.0;
    }

    return val;
}

g_val_t swap_free_func(void)
{
    char *p;
    g_val_t val;

    p = strstr(update_file(&proc_meminfo), "SwapFree:");
    if (p) {
        p = skip_token(p);
        val.f = atof(p);
    } else {
        val.f = 0.0;
    }

    return val;
}

/* --------------------------------------------------------------------------- */
/*g_val_t*/
/*mtu_func ( void )*/
/*{*/
/* We want to find the minimum MTU (Max packet size) over all UP interfaces. */
/*   g_val_t val;*/

/*   val.uint32 = get_min_mtu();*/

/* A val of 0 means there are no UP interfaces. Shouldn't happen. */
/*   return val;*/
/*}*/

/* Linux Specific, but we are in the Linux machine file. */
#define MOUNTS "/proc/mounts"

struct nlist {
    struct nlist *next;
    char *name;
};

#define DFHASHSIZE 101
static struct nlist *DFhashvector[DFHASHSIZE];

/* --------------------------------------------------------------------------- */
unsigned int DFhash(const char *s)
{
    unsigned int hashval;
    for (hashval = 0; *s != '\0'; s++)
        hashval = *s + 31 * hashval;
    return hashval % DFHASHSIZE;
}

/* --------------------------------------------------------------------------- */
/* From K&R C book, pp. 144-145 */
struct nlist *seen_before(const char *name)
{
    struct nlist *found = 0, *np;
    unsigned int hashval;

    /* lookup */
    hashval = DFhash(name);
    for (np = DFhashvector[hashval]; np; np = np->next) {
        if (!strcmp(name, np->name)) {
            found = np;
            break;
        }
    }
    if (!found) {    /* not found */
        np = (struct nlist *) malloc(sizeof(*np));
        if (!np || !(np->name = (char *) strdup(name)))
            return NULL;
        np->next = DFhashvector[hashval];
        DFhashvector[hashval] = np;
        return NULL;
    } else /* found name */
        return found;
}

/* --------------------------------------------------------------------------- */
void DFcleanup()
{
    struct nlist *np, *next;
    int i;
    for (i = 0; i < DFHASHSIZE; i++) {
        /* Non-standard for loop. Note the last clause happens at the end of the loop. */
        for (np = DFhashvector[i]; np; np = next) {
            next = np->next;
            free(np->name);
            free(np);
        }
        DFhashvector[i] = 0;
    }
}

/* --------------------------------------------------------------------------- */
int remote_mount(const char *device, const char *type)
{
    /* From ME_REMOTE macro in mountlist.h:
       A file system is `remote' if its Fs_name contains a `:'
       or if (it is of type smbfs and its Fs_name starts with `//'). */
    return ((strchr(device, ':') != 0)
            || (!strcmp(type, "smbfs") && device[0] == '/' && device[1] == '/')
            || (!strncmp(type, "nfs", 3)) || (!strcmp(type, "autofs"))
            || (!strcmp(type, "gfs")) || (!strcmp(type, "none")));
}

/* --------------------------------------------------------------------------- */
float device_space(char *mount, char *device, double *total_size, double *total_free)
{
    struct statvfs svfs;
    double blocksize;
    double free;
    double size;
    /* The percent used: used/total * 100 */
    float pct = 0.0;

    /* Avoid multiply-mounted disks - not done in df. */
    if (seen_before(device)) return pct;

    if (statvfs(mount, &svfs)) {
        /* Ignore funky devices... */
        return pct;
    }

    free = svfs.f_bavail;
    size = svfs.f_blocks;
    blocksize = svfs.f_bsize;
    /* Keep running sum of total used, free local disk space. */
    *total_size += size * blocksize;
    *total_free += free * blocksize;
    /* The percentage of space used on this partition. */
    pct = size ? ((size - free) / (float) size) * 100 : 0.0;
    return pct;
}

/* --------------------------------------------------------------------------- */
float find_disk_space(double *total_size, double *total_free)
{
    FILE *mounts;
    char procline[1024];
    char *mount, *device, *type, *mode, *other;
    /* We report in GB = 1e9 bytes. */
    double reported_units = 1e9;
    /* Track the most full disk partition, report with a percentage. */
    float thispct, max = 0.0;

    /* Read all currently mounted filesystems. */
    mounts = fopen(MOUNTS, "r");
    if (!mounts) {
        debug_msg("Df Error: could not open mounts file %s. Are we on the right OS?\n", MOUNTS);
        return max;
    }
    while (fgets(procline, sizeof(procline), mounts)) {
        device = procline;
        mount = index(procline, ' ');
        if (mount == NULL) continue;
        *mount++ = '\0';
        type = index(mount, ' ');
        if (type == NULL) continue;
        *type++ = '\0';
        mode = index(type, ' ');
        if (mode == NULL) continue;
        *mode++ = '\0';
        other = index(mode, ' ');
        if (other != NULL) *other = '\0';
        if (!strncmp(mode, "ro", 2)) continue;
        if (remote_mount(device, type)) continue;
        if (strncmp(device, "/dev/", 5) != 0 &&
            strncmp(device, "/dev2/", 6) != 0)
            continue;
        thispct = device_space(mount, device, total_size, total_free);
        debug_msg("Counting device %s (%.2f %%)", device, thispct);
        if (!max || max < thispct)
            max = thispct;
    }
    fclose(mounts);

    *total_size = *total_size / reported_units;
    *total_free = *total_free / reported_units;
    debug_msg("For all disks: %.3f GB total, %.3f GB free for users.", *total_size, *total_free);

    DFcleanup();
    return max;
}

/* --------------------------------------------------------------------------- */
g_val_t disk_free_func(void)
{
    double total_free = 0.0;
    double total_size = 0.0;
    g_val_t val;

    find_disk_space(&total_size, &total_free);

    val.d = total_free;
    return val;
}

g_val_t disk_total_func(void)
{
    double total_free = 0.0;
    double total_size = 0.0;
    g_val_t val;

    find_disk_space(&total_size, &total_free);

    val.d = total_size;
    return val;
}

g_val_t part_max_used_func(void)
{
    double total_free = 0.0;
    double total_size = 0.0;
    float most_full;
    g_val_t val;

    most_full = find_disk_space(&total_size, &total_free);

    val.f = most_full;
    return val;
}

g_val_t mac_address_func()
{
    g_val_t val;

    snprintf(val.str, MAX_G_STRING_SIZE, "%s", mac_address);

    return val;
}

//catch and analyze net packet
extern g_val_t net_val;
extern Sniffer *sniff;
g_val_t net_pack_func(void)
{
    sniff->Capture(1);
    return net_val;
}

//colletct cup_info
g_val_t cpu_info_func(void)
{
    g_val_t cpu_val;
    cpu_val.hash = NULL;

    hash_t *node = (hash_t*)malloc(sizeof(hash_t));
    strcpy(node->key, "cpu_user");
    char *cpu_use = (char*)malloc(sizeof(char)*6);
    snprintf(cpu_use, sizeof(cpu_use), "%f", cpu_user_func().f);
    node->data =  cpu_use;
    HASH_ADD_STR(cpu_val.hash, key, node);

    node = (hash_t*)malloc(sizeof(hash_t));
    strcpy(node->key, "cpu_nice");
    char *cpu_nice = (char*)malloc(sizeof(char)*6);
    snprintf(cpu_nice, sizeof(cpu_nice), "%f", cpu_nice_func().f);
    node->data =  cpu_nice;
    HASH_ADD_STR(cpu_val.hash, key, node);

    node = (hash_t*)malloc(sizeof(hash_t));
    strcpy(node->key, "cpu_steal");
    char *cpu_steal = (char*)malloc(sizeof(char)*6);
    snprintf(cpu_steal, sizeof(cpu_steal), "%f", cpu_steal_func().f);
    node->data =  cpu_steal;
    HASH_ADD_STR(cpu_val.hash, key, node);

    node = (hash_t*)malloc(sizeof(hash_t));
    strcpy(node->key, "cpu_sintr");
    char *cpu_sintr = (char*)malloc(sizeof(char)*6);
    snprintf(cpu_sintr, sizeof(cpu_sintr), "%f", cpu_sintr_func().f);
    node->data =  cpu_sintr;
    HASH_ADD_STR(cpu_val.hash, key, node);

    node = (hash_t*)malloc(sizeof(hash_t));
    strcpy(node->key, "cpu_system");
    char *cpu_system = (char*)malloc(sizeof(char)*6);
    snprintf(cpu_system, sizeof(cpu_system), "%f", cpu_system_func().f);
    node->data =  cpu_system;
    HASH_ADD_STR(cpu_val.hash, key, node);

    node = (hash_t*)malloc(sizeof(hash_t));
    strcpy(node->key, "cpu_idle");
    char *cpu_idle = (char*)malloc(sizeof(char)*6);
    snprintf(cpu_idle, sizeof(cpu_idle), "%f", cpu_idle_func().f);
    node->data =  cpu_idle;
    HASH_ADD_STR(cpu_val.hash, key, node);

    node = (hash_t*)malloc(sizeof(hash_t));
    strcpy(node->key, "cpu_aidle");
    char *cpu_aidle = (char*)malloc(sizeof(char)*6);
    snprintf(cpu_aidle, sizeof(cpu_aidle), "%f", cpu_aidle_func().f);
    node->data =  cpu_aidle;
    HASH_ADD_STR(cpu_val.hash, key, node);

    node = (hash_t*)malloc(sizeof(hash_t));
    strcpy(node->key, "cpu_wio");
    char *cpu_wio = (char*)malloc(sizeof(char)*6);
    snprintf(cpu_wio, sizeof(cpu_wio), "%f", cpu_wio_func().f);
    node->data =  cpu_wio;
    HASH_ADD_STR(cpu_val.hash, key, node);

    return cpu_val;
}

/*collect process info*/
g_val_t process_info_func()
{
    int c = 0;
  g_val_t process_val;
  process_val.list_hash = NULL;

  FILE *file = popen("ps aux --sort=%cpu", "r");
  char buff[2048];
  fgets(buff, sizeof(buff), file);

  char *p;
  list_hash_node *list;
  hash_t *node;



  while (fgets(buff, sizeof(buff), file) != NULL  && c <= 100) {
    PROCESS_INFO tmp;
    p = strtok(buff, " ");
    strcpy(tmp.user, p);

    p = strtok(NULL, " ");
    strcpy(tmp.pid, p);

    p = strtok(NULL, " ");
    strcpy(tmp.cpu_usage, p);

    p = strtok(NULL, " ");
    strcpy(tmp.mem_usage, p);

    p = strtok(NULL, " ");

    p = strtok(NULL, " ");

    p = strtok(NULL, " ");

    p = strtok(NULL, " ");
    strcpy(tmp.state, p);

    p = strtok(NULL, " ");
    strcpy(tmp.lauch_time, p);

    p = strtok(NULL, " ");
    strcpy(tmp.running_time, p);

    p = strtok(NULL, " ");
    strcpy(tmp.command, p);

      c++;
       //printf("process number:%d\t", c);
    list = (list_hash_node *)malloc(sizeof(list_hash_node));
    list->hash = NULL;

    node = (hash_t *)malloc(sizeof(hash_t));
    strcpy(node->key, "time");
    char *time_c = (char*)malloc(sizeof(15));
    sprintf(time_c,"%ld",time(NULL));
    node->data = time_c;
    HASH_ADD_STR(list->hash, key, node);

    node = (hash_t *)malloc(sizeof(hash_t));
    strcpy(node->key, "user");
    char *user = (char *)malloc(sizeof(char) * 16);
    strcpy(user, tmp.user);
    node->data = user;
    HASH_ADD_STR(list->hash, key, node);

    node = (hash_t *)malloc(sizeof(hash_t));
    strcpy(node->key, "pid");
    char *pid = (char *)malloc(sizeof(char) * 6);
    strcpy(pid, tmp.pid);
    node->data = pid;
    HASH_ADD_STR(list->hash, key, node);

    node = (hash_t *)malloc(sizeof(hash_t));
    strcpy(node->key, "state");
    char *state = (char *)malloc(sizeof(char) * 4);
    strcpy(state, tmp.state);
    node->data = state;
    HASH_ADD_STR(list->hash, key, node);

    node = (hash_t *)malloc(sizeof(hash_t));
    strcpy(node->key, "cpu_usage");
    char *proc_cpu_usage = (char *)malloc(sizeof(char) * 4);
    strcpy(proc_cpu_usage, tmp.cpu_usage);
    node->data = proc_cpu_usage;
    HASH_ADD_STR(list->hash, key, node);

    node = (hash_t *)malloc(sizeof(hash_t));
    strcpy(node->key, "mem_usage");
    char *proc_mem_usage = (char *)malloc(sizeof(char) * 4);
    strcpy(proc_mem_usage, tmp.mem_usage);
    node->data = proc_mem_usage;
    HASH_ADD_STR(list->hash, key, node);

    node = (hash_t *)malloc(sizeof(hash_t));
    strcpy(node->key, "lauch_time");
    char *proc_lauchtime = (char *)malloc(sizeof(char) * 10);
    strcpy(proc_lauchtime, tmp.lauch_time);
    node->data = proc_lauchtime;
    HASH_ADD_STR(list->hash, key, node);

    node = (hash_t *)malloc(sizeof(hash_t));
    strcpy(node->key, "running_time");
    char *running_time = (char *)malloc(sizeof(char) * 10);
    strcpy(running_time, tmp.running_time);
    node->data = running_time;
    HASH_ADD_STR(list->hash, key, node);

    node = (hash_t *)malloc(sizeof(hash_t));
    strcpy(node->key, "command");
    char *command = (char *)malloc(sizeof(char) * 64);
    strcpy(command, tmp.command);
    node->data = command;
    HASH_ADD_STR(list->hash, key, node);

      //printf("hash list success\t");


    LL_APPEND(process_val.list_hash, list);

      //printf("the command of process:%s\n", command);
  }



  return process_val;
}


g_val_t file_log_func()
{
    g_val_t file_log_val;
    file_log_val.list_hash = NULL;

    char file_monitor_log[FILE_CACHE_LEN][MAX_G_STRING_SIZE] = {NULL};
    int cur = 0;
    read_filemonitor_4Cache((char **)file_monitor_log, cur);

    char *p;
    list_hash_node *list;
    hash_t *node;

    int count = 0;
    while (count < cur) {

      list = (list_hash_node *)malloc(sizeof(list_hash_node));
      list->hash = NULL;

      p = strtok(file_monitor_log[count], "-");
      node = (hash_t *)malloc(sizeof(hash_t));
      strcpy(node->key, "time");
      char *time_c = (char*)malloc(sizeof(15));
      strcpy(time_c, p);
      node->data = time_c;
      HASH_ADD_STR(list->hash, key, node);

      p = strtok(NULL, "-");
      node = (hash_t *)malloc(sizeof(hash_t));
      strcpy(node->key, "file");
      char *file_c = (char*)malloc(sizeof(40));
      strcpy(file_c, p);
      node->data = file_c;
      HASH_ADD_STR(list->hash, key, node);

      p = strtok(NULL, "-");
      node = (hash_t *)malloc(sizeof(hash_t));
      strcpy(node->key, "operat");
      char *op_c = (char*)malloc(sizeof(9));
      strcpy(op_c, p);
      node->data = op_c;
      HASH_ADD_STR(list->hash, key, node);

      LL_APPEND(file_log_val.list_hash, list);
    }

    return file_log_val;
}


/*collect mem info*/
g_val_t mem_info_func(void)
{
    g_val_t mem_val;
    mem_val.hash = NULL;

    hash_t *node = (hash_t*)malloc(sizeof(hash_t));
    strcpy(node->key, "mem_total");
    char *mem_total = (char*)malloc(sizeof(char)*6);
    snprintf(mem_total, sizeof(mem_total), "%f", mem_total_func().f);
    node->data =  mem_total;
    HASH_ADD_STR(mem_val.hash, key, node);

    node = (hash_t*)malloc(sizeof(hash_t));
    strcpy(node->key, "mem_free");
    char *mem_free = (char*)malloc(sizeof(char)*6);
    snprintf(mem_free, sizeof(mem_free), "%f", mem_free_func().f);
    node->data =  mem_free;
    HASH_ADD_STR(mem_val.hash, key, node);

    node = (hash_t*)malloc(sizeof(hash_t));
    strcpy(node->key, "mem_shared");
    char *mem_shared = (char*)malloc(sizeof(char)*6);
    snprintf(mem_shared, sizeof(mem_shared), "%f", mem_shared_func().f);
    node->data =  mem_shared;
    HASH_ADD_STR(mem_val.hash, key, node);

    node = (hash_t*)malloc(sizeof(hash_t));
    strcpy(node->key, "mem_cached");
    char *mem_cached = (char*)malloc(sizeof(char)*6);
    snprintf(mem_cached, sizeof(mem_shared), "%f", mem_cached_func().f);
    node->data =   mem_cached;
    HASH_ADD_STR(mem_val.hash, key, node);

    node = (hash_t*)malloc(sizeof(hash_t));
    strcpy(node->key, "mem_buffers");
    char *mem_buffers = (char*)malloc(sizeof(char)*6);
    snprintf(mem_buffers, sizeof(mem_buffers), "%f", mem_buffers_func().f);
    node->data =  mem_buffers;
    HASH_ADD_STR(mem_val.hash, key, node);

    return mem_val;
}

/*collection disk info*/
g_val_t disk_info_func(void)
{
    g_val_t disk_val;
    disk_val.hash = NULL;

    hash_t *node = (hash_t*)malloc(sizeof(hash_t));
    strcpy(node->key, "disk_total");
    char *disk_total = (char*)malloc(sizeof(char)*6);
    snprintf(disk_total, sizeof(disk_total), "%f", disk_total_func().f);
    node->data =  disk_total;
    HASH_ADD_STR(disk_val.hash, key, node);

    node = (hash_t*)malloc(sizeof(hash_t));
    strcpy(node->key, "disk_free");
    char *disk_free = (char*)malloc(sizeof(char)*6);
    snprintf(disk_free, sizeof(disk_free), "%f", disk_free_func().f);
    node->data =  disk_free;
    HASH_ADD_STR(disk_val.hash, key, node);

    return disk_val;
}
