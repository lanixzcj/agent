//
// Created by lan on 12/20/16.
//
#include <stdio.h>
#include <stdlib.h>
#include <net.h>
#include <net.c>
#include "debug_msg.h"
#include "conf.h"
#include <time.h>
#include <cJSON.h>
#include "client.h"
#include "metrics.h"
#include <errno.h>
#include <http-client-c.h>
#include <utlist.h>
#include <pthread.h>
#include "thpool.h"
#include "mon_value.h"
#include <string>
#include <crafter.h>
#include <semaphore.h>
#include <fstream>
using namespace std;
using namespace Crafter;
extern config_t config;
g_socket *tcp_client_socket;
pthread_mutex_t send_socket_mutex = PTHREAD_MUTEX_INITIALIZER;
g_socket *tcp_server_socket;
hash_t *host_data;
User_t *user;
string getInterface();
void PacketHandler(Packet* sniff_packet, void* user);
// get the net interface
string iface = getInterface();
/*
 * First, you should create a sniffer
 * - 1st argument: Filter expression (tcpdump syntax)
 * - 2nd argument: Interface
 * - 3rd argument: A function that will be executed when a packet
 * captured satisfies the filter expression (the default behavior is to
 * print the packets to STDOUT).
 */
// net sniffer z result
Sniffer sniff("",iface,PacketHandler);

/*Producer Consumer Model for collection and send */
cJSON * cache[1024] = {NULL};
int pos;             //the position of cache
sem_t full;
sem_t empty;
sem_t mutex;
void write2cache(cJSON *wait_to_send)
{
    sem_wait(&empty);
    sem_wait(&mutex);
    cache[pos++] = wait_to_send;
    sem_post(&mutex);
    sem_post(&full);
}
cJSON *readFromCache()
{
    cJSON* temp = NULL;
    sem_wait(&full);
    sem_wait(&mutex);
    temp = cache[--pos];
    sem_post(&mutex);
    sem_post(&empty);
    return temp;
}
g_val_t net_val;
/**
 * get value_to_str
 * @param msg
 * @return
 */
char *metric_value_to_str(monitor_value_msg *msg)
{
    static char value[1024];
    if (!msg) {
        return "unknown";
    }

    switch (msg->type) {
        case MON_VALUE_STRING:
            strcpy(value, msg->val.str);
            return value;
        case MON_VALUE_UNSIGNED_16INT:
            snprintf(value, 1024, msg->format, msg->val.uint16);
            return value;
        case MON_VALUE_16INT:
            snprintf(value, 1024, msg->format, msg->val.int16);
            return value;
        case MON_VALUE_UNSIGNED_32INT:
            snprintf(value, 1024, msg->format, msg->val.uint32);
            return value;
        case MON_VALUE_32INT:
            snprintf(value, 1024, msg->format, msg->val.int32);
            return value;
        case MON_VALUE_FLOAT:
            snprintf(value, 1024, msg->format, msg->val.f);
            return value;
        case MON_VALUE_DOUBLE:
            snprintf(value, 1024, msg->format, msg->val.d);
            return value;
        default:
            return "unknown";
    }
}

/**
 * get value_to_json item
 * @param msg
 * @return
 */
cJSON *metric_value_to_cjson(monitor_value_msg *msg)
{
    if (!msg) {
        return NULL;
    }

    cJSON *item, *tmp_item;
    list_node *node, *tmp;
    hash_t *node_h, *tmp_h;
    list_hash_node *node_l, *tmp_l;
    switch (msg->type) {
        case MON_VALUE_LIST:
            item = cJSON_CreateArray();
            LL_FOREACH_SAFE(msg->val.list, node, tmp) {
                cJSON_AddItemToArray(item, cJSON_CreateString(node->string));
            }
            return item;
        case MON_VALUE_HASH:
            item = cJSON_CreateObject();
            HASH_ITER(hh, msg->val.hash, node_h, tmp_h) {
                cJSON_AddItemToObject(item, node_h->key, cJSON_CreateString((char*)node_h->data));
            }
            return item;
        case MON_VALUE_LIST_HASH:
            item = cJSON_CreateArray();
            LL_FOREACH_SAFE(msg->val.list_hash, node_l, tmp_l) {
                tmp_item = cJSON_CreateObject();
                HASH_ITER(hh, node_l->hash, node_h, tmp_h) {
                   // cout<<node_h->data<<endl;
                    cJSON_AddItemToObject(tmp_item, node_h->key, cJSON_CreateString((char*)node_h->data));
                }
                cJSON_AddItemToArray(item, tmp_item);
            }
            return item;
        default:
            return cJSON_CreateObject();
    }
}

char *host_metric_type(monitor_value_types type)
{
    switch(type) {
        case MON_VALUE_UNKNOWN:
            return "unknown";
        case MON_VALUE_STRING:
            return "string";
        case MON_VALUE_UNSIGNED_16INT:
            return "uint16";
        case MON_VALUE_16INT:
            return "int16";
        case MON_VALUE_UNSIGNED_32INT:
            return "uint32";
        case MON_VALUE_32INT:
            return "int32";
        case MON_VALUE_FLOAT:
            return "float";
        case MON_VALUE_DOUBLE:
            return "double";
        case MON_VALUE_LIST:
            return "list";
        case MON_VALUE_HASH:
            return "hash";
        case MON_VALUE_LIST_HASH:
            return "list_hash";
    }
    return "undef";
}

int collect_metric(hash_t *hash, cJSON *send_data, time_t *now)
{
    metric_callback_t *metric_callback = (metric_callback_t*)hash->data;

    if (metric_callback && now) {
        cJSON *metrics = cJSON_GetObjectItem(send_data, "metrics");
        if (metric_callback->next_collect <= *now && metrics) {
            debug_msg("metric '%s' being collected now\n",
                      metric_callback->msg.name);
            metric_callback->last = metric_callback->msg.val;
            metric_callback->msg.val = metric_callback->cb();

            cJSON *metric = cJSON_GetObjectItem(metrics, metric_callback->msg.name);
            switch (metric_callback->msg.type) {
                case MON_VALUE_LIST:
                    cJSON_ReplaceItemInObject(metric, "value",
                                              metric_value_to_cjson(&metric_callback->msg));
                    break;
                case MON_VALUE_HASH:
                    cJSON_ReplaceItemInObject(metric, "value",
                                              metric_value_to_cjson(&metric_callback->msg));
                    break;
                case MON_VALUE_LIST_HASH:
                    cJSON_ReplaceItemInObject(metric, "value",
                                              metric_value_to_cjson(&metric_callback->msg));
                    break;
                default:
                    cJSON_ReplaceItemInObject(metric, "value",
                                              cJSON_CreateString(metric_value_to_str(&metric_callback->msg)));
                    break;
            }

            if (metric_callback->collect_every >= 0) {
                metric_callback->next_collect = *now + metric_callback->collect_every;
            } else {
                metric_callback->next_collect = *now + 31536000;
            }
        } else if (metric_callback->next_collect > *now && metrics) {
            cJSON_DeleteItemFromObject(metrics, metric_callback->msg.name);
        }
    }

    return 0;
}

void send_metric(cJSON* send_json)
{
    //pthread_mutex_lock(&send_socket_mutex);
    tcp_client_socket = tcp_socket_client(config.remote_host, config.remote_port);
    if (tcp_client_socket == NULL) {
        err_quit("can't create tcp socket.\n");
    }

    cJSON *host_json = cJSON_GetObjectItem(send_json, "host");
    if (host_json) {
        cJSON_ReplaceItemInObject(host_json, "localtime", cJSON_CreateNumber(time(NULL)));
    }

    char* send_data = cJSON_Print(send_json);
    int len = strlen(send_data);
    int ret;
    debug_msg(send_data);
    SYS_CALL(ret, send(tcp_client_socket->sockfd, send_data, len, 0));
    if (ret < 0) {
        err_quit("send error!\n");
    }

    char remote_ip[16];
    inet_ntop(AF_INET, &G_SOCKADDR_IN(tcp_client_socket->sa).sin_addr, remote_ip, 16);
    debug_msg("host has been sent to %s\n", remote_ip);
    close_socket(tcp_client_socket);
    //pthread_mutex_unlock(&send_socket_mutex);
}

int when_next_event_occurs(hash_t *hash, time_t *next)
{
    metric_callback_t *metric_callback = (metric_callback_t*)hash->data;

    if (metric_callback && next) {
        time_t min = metric_callback->next_collect;
        if (*next == -1) {
            *next = min;
        } else {
            if (min < *next) {
                *next = min;
            }
        }
    }

    return 0;
}

time_t collection_group_collect_and_send(Host_t *host, time_t now) {
    time_t next = -1;
    cJSON *wait_to_send = cJSON_Duplicate(host->send_data, 1);
    hash_t *tmp, *node;
    HASH_ITER(hh, host->metrics, node, tmp) {
        collect_metric(node, wait_to_send, &now);
    }
    write2cache(wait_to_send);
   // send_metric(wait_to_send);
    HASH_ITER(hh, host->metrics, node, tmp) {
        when_next_event_occurs(node, &next);
    }
    return next < now ? now + 1 : next;
}

/**
 * accept safe strategy
 * @param arg
 */
/*safe excer*/
void safer(char *data)
{
    cJSON *json;
    json = cJSON_Parse(data);
    json = cJSON_GetObjectItem(json,"net");
    if (!json) {
        err_quit("Error before: [%s]\n",cJSON_GetErrorPtr());
    }
    debug_msg(data);

    string commend;
    string str1 = "iptables -A ";
    string str2 = " -s ";
    string str3 = " -j DROP\n";
    system("sudo iptables -F");
    ofstream fout("safe.sh",ios::trunc);
    for (int i = 0;i < cJSON_GetArraySize(json);i++) {
        cJSON *item = cJSON_GetArrayItem(json, i);
        cJSON *ip = cJSON_GetObjectItem(item, "ip");
        cJSON *chan = cJSON_GetObjectItem(item, "rule");
        fout<<str1<<chan->valuestring<<str2<<ip->valuestring<<str3;
        commend = str1+chan->valuestring+str2+ip->valuestring+" -j DROP";
        system(commend.data());
    }
    fout.close();
    //system("./safe.sh");
    cJSON_Delete(json);
}

void tcp_accept_thread(void *arg)
{
    socklen_t len;
    g_socket *client_socket;
    char  remoteip[16];

    client_socket = (g_socket*)malloc(sizeof(g_socket));
    if (!tcp_server_socket) {
        err_quit("Create server socket failed.\n");
    }

    for (;;) {
        char *buffer = (char*)malloc(BUFFER_SIZE);

        SYS_CALL(client_socket->sockfd, accept(tcp_server_socket->sockfd, &(client_socket->sa), &len));
        inet_ntop(AF_INET, &G_SOCKADDR_IN(client_socket->sa).sin_addr, remoteip, 16);

        tcp_receive(client_socket, buffer, BUFFER_SIZE, 10000);

        cout<<"buffer"<<endl;
        cout<<buffer<<endl;
        safer(buffer);
        cout<<"buffer"<<endl;

        debug_msg(buffer);
        if (strlen(buffer) != 0) {
            send(client_socket->sockfd, "0", 3, 0);
        } else {
            send(client_socket->sockfd, "1", 3, 0);
        }

        if (client_socket->sockfd > 0) {
            close(client_socket->sockfd);
        }
    }
}

void group_collection_thread(void *arg)
{
    hash_t *node = (hash_t*)arg;
    if (!node) {
        debug_msg("Bad host node.");
        return;
    }
    Host_t *host = (Host_t*)node->data;
    if (!host) {
        debug_msg("Bad host data.");

        return;
    }
    time_t now, next, wait;
    now = next = time(NULL);

    for(;;) {
        wait = next >= now ? next - now : 1;

        debug_msg("group %s wait %d to next event occurs\n",node->key, wait);
        sleep(wait);
        now = time(NULL);

        if (now < next) {
            continue;
        }

        next = collection_group_collect_and_send(host, now);
    }
}

/**
 * login by http
 * @param username
 * @param password
 * @return
 */
int login(char *username, char *password)
{
    int i;
    cJSON *json;
    char data_buf[BUFFER_SIZE] = {'\0'};
    char url_buf[BUFFER_SIZE] = {'\0'};
    user = (User_t*)malloc(sizeof(User_t));
    user->username = (char*)malloc(sizeof(username));
    user->permission_list = NULL;

    g_val_t val = mac_address_func();

    sprintf(url_buf, "http://%s:8000/login/", config.remote_host);
    sprintf(data_buf, "username=%s&password=%s&mac_address=%s", username, password, val.str);
    struct http_response *hresp = http_post(url_buf, "User-agent:MyUserAgent",
                                            data_buf);
    if (hresp && strcmp(hresp->status_text, "OK") == 0) {
        debug_msg(hresp->body);
        json = cJSON_Parse(hresp->body);
        if (!json) {
            debug_msg("Error before: [%s]\n",cJSON_GetErrorPtr());
        } else {
            cJSON *result = cJSON_GetObjectItem(json, "result");
            cJSON *mactch = cJSON_GetObjectItem(json, "mac_address_match");
            if (result && result->valueint == cJSON_True &&
                    mactch && mactch->valueint == cJSON_True) {

                debug_msg("Login success.");
                strcpy(user->username, username);

                cJSON *permissions = cJSON_GetObjectItem(json, "permissions");
                if (permissions) {
                    for (i = 0; i < cJSON_GetArraySize(permissions); i++) {
                        cJSON *name = cJSON_GetArrayItem(permissions, i);
                        list_node *node = (list_node *) malloc(sizeof(list_node));
                        strcpy(node->string, name->valuestring);
                        LL_APPEND(user->permission_list, node);

                    }
                }

                return 0;
            } else if (result && result->valueint == cJSON_True &&
                       mactch && mactch->valueint == cJSON_False) {
                debug_msg("Permission denied.");
            } else {
                debug_msg("Please enter the correct username and password.");
            }
        }
    } else {
        debug_msg("server error.");
    }

    return -1;
}

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

        /* Summarize Ethernet data */
        Ethernet* Ethernet_layer = sniff_packet->GetLayer<Ethernet>();
        if(Ethernet_layer)
        {
            node = (hash_t*)malloc(sizeof(hash_t));
            strcpy(node->key, "source_MAC");
            string *sMACp = new string;
            *sMACp = Ethernet_layer->GetSourceMAC();
            char *sMACcp= (char *) (*sMACp).data();
           // cout<<sMACcp<<endl;
            node->data = sMACcp;
            HASH_ADD_STR(net_val.hash, key, node);

            node = (hash_t*)malloc(sizeof(hash_t));
            strcpy(node->key, "des_MAC");
            string *dMACp = new string;
            *dMACp = Ethernet_layer->GetDestinationMAC();
            char *dMACcp= (char *) (*dMACp).data();
            //cout<<dMACcp<<endl;
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
            //cout<<*sIPp<<endl;
            node->data = sIPcp;
            HASH_ADD_STR(net_val.hash, key, node);

            node = (hash_t*)malloc(sizeof(hash_t));
            strcpy(node->key, "des_IP");
            string *dIPp = new string;
            *dIPp = IP_layer->GetDestinationIP();
            char *dIPcp= (char *) (*dIPp).data();
            //cout<<*dIPp<<endl;
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
            //cout<<sTCPcp<<endl;
            node->data = sTCPcp;
            HASH_ADD_STR(net_val.hash, key, node);

            node = (hash_t*)malloc(sizeof(hash_t));
            strcpy(node->key, "des_port");
            short unsigned int *dTCPp = new short unsigned int;
            *dTCPp = tcp_layer->GetDstPort();
            char *dTCPcp = (char*)malloc(sizeof(char)*6);
            snprintf(dTCPcp, sizeof(dTCPcp), "%d", *dTCPp);
            //cout<<dTCPcp<<endl;
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
            //cout<<sUDPcp<<endl;
            node->data = sUDPcp;
            HASH_ADD_STR(net_val.hash, key, node);

            node = (hash_t*)malloc(sizeof(hash_t));
            strcpy(node->key, "des_port");
            short unsigned int *dUCPp = new short unsigned int;
            *dUCPp = UDP_layer->GetDstPort();
            char *dUDPcp = (char*)malloc(sizeof(char)*6);
            snprintf(dUDPcp, sizeof(dUDPcp), "%d", *dUCPp);
            //cout<<dUDPcp<<endl;
            node->data = dUDPcp;
            HASH_ADD_STR(net_val.hash, key, node);
        }
    }
}
/*send thead*/
void send_thread(void *arg)
{
    cJSON * wait_to_send;
    while(1)
    {
        wait_to_send = readFromCache();
        send_metric(wait_to_send);

    }
}

/*wait to connet host*/
void wait_to_connet()
{
    int flag = 1;
    while(flag)
    {
        tcp_client_socket = tcp_socket_client(config.remote_host, config.remote_port);
        if (tcp_client_socket == NULL) {
            sleep(10);
        } else
        {
            flag = 0;
        }
    }
}

int main() {
    char absolute_path[BUFFER_SIZE];

    int ret;

    ret = readlink("/proc/self/exe", absolute_path, BUFFER_SIZE);
    if (ret < 0 || ret >= BUFFER_SIZE) {
        err_quit("Fail to read current path.");
    } else {
        // TODO:配置文件与可执行程序同级，clion项目中可执行文件在源文件下一级目录
        char *p = strrchr(absolute_path, '/');
        *p = '\0';
//        p = strrchr(absolute_path, '/');
//        *p = '\0';
    }

    metric_init();
    parse_config_file(str_cat(absolute_path, "/client.json"));

    // TODO:post密码是否不应该明文，加密后认证又暴露数据库内容，使用非对称加密？
//    ret = login("zzz", "aa123123");
//    if (ret != 0) {
//        return 0;
//    }

    //init Producer Consumer Model
    pos = 0;
    sem_init(&full,0,0);
    sem_init(&empty,0,1024);
    sem_init(&mutex,0,1);

    wait_to_connet();

    pthread_mutex_init(&send_socket_mutex, NULL);
    int count = HASH_COUNT(host_data);
    threadpool thpool = thpool_init(count + 2);

    //recive thread
    ret = thpool_add_work(thpool, tcp_accept_thread, NULL);
    //send thread
    ret = thpool_add_work(thpool, send_thread, NULL);
    //collect thread
    hash_t *node, *tmp;
    HASH_ITER(hh, host_data, node, tmp) {
        thpool_add_work(thpool, group_collection_thread, node);
    }

    thpool_wait(thpool);

    return 0;
}