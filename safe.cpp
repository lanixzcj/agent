//
// Created by can on 17-5-3.
//
#include "safe.h"
using namespace std;
/*net safe excer*/
void safer(char *data)
{
    cJSON *json;
    json = cJSON_Parse(data);
    if((cJSON_GetObjectItem(json,"net")))
    {
        json = cJSON_GetObjectItem(json,"net");
        net_safer(json);
    }
    else if((cJSON_GetObjectItem(json,"file")))
    {
        json = cJSON_GetObjectItem(json,"file");
        file_safer(json);
    }
    else
    {
        err_quit("Error before: [%s]\n",cJSON_GetErrorPtr());
    }
    debug_msg(data);
}

void net_safer(cJSON *json)
{
    string commend;
    string str1 = "iptables -A ";
    string str2 = " -s ";
    string str3 = " -j DROP\n";
    system("sudo iptables -F");
    ofstream fout("netsafe",ios::trunc);
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

/*file safe excer*/
void file_safer(cJSON *json)
{
    string commend;
    string str1 = "chmod ";
    system("sudo iptables -F");
    ofstream fout("filesafe",ios::trunc);
    for (int i = 0;i < cJSON_GetArraySize(json);i++) {
        cJSON *item = cJSON_GetArrayItem(json, i);
        cJSON *path = cJSON_GetObjectItem(item, "file");
        cJSON *permission = cJSON_GetObjectItem(item, "permission");
        commend = str1 + permission->valuestring + " " + path->valuestring;
        fout<<commend+"\n";
        system(commend.data());
    }
    fout.close();
    cJSON_Delete(json);
}
