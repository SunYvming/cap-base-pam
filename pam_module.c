#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <security/pam_modules.h>
#include "list/list.h"
#include <sys/types.h>
#include <sys/capability.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <errno.h>

extern int errno;

typedef struct
{
    char* filename;
    pid_t pid;
    list_t* addcap_list;
    list_t* delcap_list;
}cap_list_t;

int cap_is_set(cap_t caps, cap_value_t cap){
    cap_flag_value_t cap_flag_e;
    cap_flag_value_t cap_flag_p;
    cap_flag_value_t cap_flag_i;
    cap_get_flag(caps, cap, CAP_EFFECTIVE, &cap_flag_e);
    cap_get_flag(caps, cap, CAP_PERMITTED, &cap_flag_p);
    cap_get_flag(caps, cap, CAP_INHERITABLE, &cap_flag_i);
    return (cap_flag_e||cap_flag_p||cap_flag_i);
}

int cap_inh_is_set(cap_t caps, cap_value_t cap){
    cap_flag_value_t cap_flag_i;
    cap_get_flag(caps, cap, CAP_INHERITABLE, &cap_flag_i);
    return cap_flag_i;
}

void enable_caps(cap_list_t *cap,cap_value_t * cap_values, int len)
{
    char *path_p = cap->filename;
    pid_t pid =cap->pid;
    cap_t caps = NULL;
    if(path_p != NULL)
        caps = cap_get_file(path_p);
    else if(pid != -1)
        caps = cap_get_pid(pid);
    else return;

    if(caps != NULL)
    {
        cap_set_flag(caps,CAP_PERMITTED,len,cap_values,CAP_SET);
        cap_set_flag(caps,CAP_EFFECTIVE,len,cap_values,CAP_SET);
        cap_set_flag(caps,CAP_INHERITABLE,len,cap_values,CAP_SET);
    }
    else return;

    if(path_p != NULL)
    {
        if(cap_set_file(path_p,caps)) 
            syslog(LOG_ERR, "pam-login-cap:cap_set_file() ERROR:code:%d, %s",errno,strerror(errno));
        else syslog(LOG_INFO, "pam-login-cap:成功添加权限");
    }
    else if(pid != -1)
    {
        if(cap_set_proc(caps))
            syslog(LOG_ERR, "pam-login-cap:cap_set_proc() ERROR:code:%d, %s",errno,strerror(errno));
        else syslog(LOG_INFO, "pam-login-cap:成功添加权限");
    }
    cap_free(caps);
}

void disable_caps(cap_list_t *cap,cap_value_t * cap_values, int len)
{
    char *path_p = cap->filename;
    pid_t pid =cap->pid;
    cap_t caps = NULL;
    if(path_p != NULL)
        caps = cap_get_file(path_p);
    else if(pid != -1)
        caps = cap_get_pid(pid);
    else return;

    if(caps != NULL)
    {
        cap_set_flag(caps,CAP_PERMITTED,len,cap_values,CAP_CLEAR);
        cap_set_flag(caps,CAP_EFFECTIVE,len,cap_values,CAP_CLEAR);
        cap_set_flag(caps,CAP_INHERITABLE,len,cap_values,CAP_CLEAR);
    }
    else return;

    if(path_p != NULL)
    {
        if(cap_set_file(path_p,caps)) 
            syslog(LOG_ERR, "pam-login-cap:cap_set_file() ERROR:code:%d, %s",errno,strerror(errno));
        else syslog(LOG_INFO, "pam-login-cap:成功添加权限");
    }
    else if(pid != -1)
    {
        if(cap_set_proc(caps))
            syslog(LOG_ERR, "pam-login-cap:cap_set_proc() ERROR:code:%d, %s",errno,strerror(errno));
        else syslog(LOG_INFO, "pam-login-cap:成功添加权限");
    }
    cap_free(caps);
}

void fix_caps(char* path_p){
    cap_t caps = cap_get_file(path_p);
    char * cap_text = cap_to_text(caps, NULL);
    if(cap_text==NULL)
    {
        syslog(LOG_ERR, "pam-login-cap:cap结构已被破坏，尝试进行重建");
        char * argv[] = {"setcap","",path_p,NULL};
        pid_t pid;
        int rtn;
        pid = fork();
        if(pid==0)
        {
            execv("/bin/setcap", argv);
            syslog(LOG_ERR, "pam-login-cap:cap结构重建失败 ERROR:%d,%s",errno,strerror(errno));
            exit(errno);
        }
        else
        {
            wait(&rtn);
            if(rtn == 0)
                syslog(LOG_INFO, "pam-login-cap:成功重建权限");
        }
    }
    else
        syslog(LOG_INFO, "pam-login-cap:cap结构正常,不进行修复");
    cap_free(caps);
}

void print_caps_file(char* path_p){
    cap_t caps = cap_get_file(path_p);
    ssize_t y = 0;
    syslog(LOG_INFO, "pam-login-cap:文件%s的权限为%s",path_p, cap_to_text(caps, &y));
    fflush(0);
    cap_free(caps);
}

void print_caps_process(pid_t pid){
    cap_t caps = cap_get_pid(pid);
    ssize_t y = 0;
    syslog(LOG_INFO, "pam-login-cap:进程%d的权限为%s",pid, cap_to_text(caps, &y));
    fflush(0);
    cap_free(caps);
}

void change_caps(cap_list_t *cap){

    char *path_p = cap->filename;
    pid_t pid =cap->pid;
    if(path_p != NULL)
        fix_caps(path_p);
    list_t *addcap_list = cap->addcap_list;
    list_t *delcap_list = cap->delcap_list;

    //只作权限解算
    if(path_p !=NULL)
    {
        cap_t caps = cap_get_file(path_p);

        //确认希望添加的权限未存在
        list_node_t *cap_node;
        list_iterator_t *it = list_iterator_new(addcap_list, LIST_HEAD);
        cap_value_t cap_values[255] = {0};
        int len = 0;
        while((cap_node = list_iterator_next(it))) {
            cap_value_t cap_value;
            cap_from_name(cap_node->val,&cap_value);
            if(cap_is_set(caps,cap_value))
            {
                syslog(LOG_INFO, "pam-login-cap:权限%s已存在,不进行权限添加操作",cap_node->val);
                list_remove(addcap_list,cap_node);
            }
            else{
                cap_values[len] = cap_value;
                len++;
            }
        }
        list_iterator_destroy(it);
        if(len>0)
            enable_caps(cap,cap_values,len);
        
        //确认希望删除的权限已存在
        it = list_iterator_new(delcap_list, LIST_HEAD);
        len = 0;
        while((cap_node = list_iterator_next(it))) {
            cap_value_t cap_value;
            cap_from_name(cap_node->val,&cap_value);
            if(!cap_is_set(caps,cap_value))
            {
                syslog(LOG_INFO, "pam-login-cap:权限%s不存在,不进行权限删除操作",cap_node->val);
                list_remove(delcap_list,cap_node);
            }
            else{
                cap_values[len] = cap_value;
                len++;
            }
        }
        list_iterator_destroy(it);
        if(len>0)
            disable_caps(cap,cap_values,len);
        cap_free(caps);
        print_caps_file(path_p);
    }
    else if(pid != -1)
    {
        cap_t caps = cap_get_file(pid);

        //由于该进程是特权进程，所以不需要确认权能是否存在，只添加inheritable权限
        list_node_t *cap_node;
        list_iterator_t *it = list_iterator_new(addcap_list, LIST_HEAD);
        cap_value_t cap_values[255] = {0};
        int len = 0;
        while((cap_node = list_iterator_next(it))) {
            cap_value_t cap_value;
            cap_from_name(cap_node->val,&cap_value);
            cap_values[len] = cap_value;
            len++;
        }
        list_iterator_destroy(it);
        if(len>0)
            enable_caps(cap,cap_values,len);
        
        //对特权进程删除权能没有意义，所以不进行删除操作

        cap_free(caps);
        print_caps_process(pid);
    }

}

void undo_change_caps(cap_list_t* cap)
{
    list_t * temp =NULL;
    if(cap->filename==NULL && cap->pid!=-1)
    {
        //进程自动死亡，不需要撤销权能
        return;
    }
    temp = cap->delcap_list;
    cap->delcap_list = cap->addcap_list;
    cap->addcap_list = temp;
    change_caps(cap);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    syslog(LOG_INFO, "pam-login-cap:进入认证服务");
    syslog(LOG_ERR,"pam-login-cap:认证服务：这一服务不应被调用");
    return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    syslog(LOG_INFO, "pam-login-cap:进入凭证修改服务");
    syslog(LOG_ERR,"pam-login-cap:凭证修改服务：这一服务不应被调用");
    return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    syslog(LOG_INFO, "pam-login-cap:进入权限认证服务");
    syslog(LOG_ERR,"pam-login-cap:权限认证服务：这一服务不应被调用");
    return PAM_SERVICE_ERR;
}



PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const char *user = NULL;
    syslog(LOG_INFO, "pam-login-cap:进入会话");

    int pam_code = pam_get_user(pamh, &user, "USERNAME: ");
	if (pam_code != PAM_SUCCESS) {
        syslog(LOG_ERR, "pam-login-cap:Can't get username");
		return PAM_PERM_DENIED;
	}
    else
        syslog(LOG_INFO, "pam-login-cap:user:%s",user);

    pid_t pid = -1;
    char cmd[255] = "ps -f| grep bash";
    FILE *ptr;
    if((ptr = popen(cmd, "r")) != NULL)
    {
        char buf_ps[1024];
        if(fgets(buf_ps, sizeof(buf_ps), ptr) != NULL)
        {
            strtok(buf_ps, " ");
            strtok(NULL, " ");
            pid = strtol(strtok(NULL, " "),NULL,10);
        }
        pclose(ptr);
        ptr = NULL;
    }
    else
        syslog(LOG_ERR, "pam-login-cap:获取进程pid失败");

    if (pid ==-1)
        syslog(LOG_ERR, "pam-login-cap:获取的进程pid非法");

    //开始根据配置设置权能
    list_t * cap_list = list_new();

    for (int i = 0; i < argc; i++) {
        if(strncmp(argv[i],"user=",5) == 0)
        {
            char * p = strtok(argv[i],",");
            const char * user_name = &p[5];
            if(strcmp(user,user_name)!=0 && strcmp(user_name,"*")!=0)
                continue;
            p = strtok(NULL,",");
            
            if (strncmp(p, "file=", 5) == 0)
            {
                const char * file_name = &p[5];
                syslog(LOG_INFO, "pam-login-cap:对文件设置权能,目标文件:%s",file_name);

                cap_list_t * cap = malloc(sizeof(cap_list_t));
                cap->filename = file_name;
                cap->pid = -1;
                list_t * file_addcap = list_new();
                cap->addcap_list = file_addcap;
                list_t * file_delcap = list_new();
                cap->delcap_list = file_delcap;

                for(p = strtok(NULL,",");p;p = strtok(NULL,","))
                {
                    if(strncmp(p,"+",1)==0)
                    {
                        char * cap_name = &p[1];
                        syslog(LOG_INFO, "pam-login-cap:增加权能:%s",cap_name);
                        list_rpush(file_addcap, list_node_new(cap_name));
                    }
                    else if(strncmp(p,"-",1)==0)
                    {
                        char * cap_name = &p[1];
                        syslog(LOG_INFO, "pam-login-cap:删除权能:%s",cap_name);
                        list_rpush(file_delcap, list_node_new(cap_name));
                    }
                    else
                        syslog(LOG_ERR, "pam-login-cap:权能配置错误:%s",p);
                }
                list_rpush(cap_list, list_node_new(cap));
                change_caps(cap);
            }
            else if(strncmp(p, "process", 7) == 0){
                if(pid == -1)
                    continue;

                syslog(LOG_INFO, "pam-login-cap:对进程设置权能，目标进程:%d",pid);
                
                cap_list_t * cap = malloc(sizeof(cap_list_t));
                cap->filename = NULL;
                cap->pid = pid;
                list_t * process_addcap = list_new();
                cap->addcap_list = process_addcap;
                list_t * process_delcap = list_new();
                cap->delcap_list = process_delcap;

                for(p = strtok(NULL,",");p;p = strtok(NULL,","))
                {
                    if(strncmp(p,"+",1)==0)
                    {
                        char * cap_name = &p[1];
                        syslog(LOG_INFO, "pam-login-cap:增加权能:%s",cap_name);
                        list_rpush(process_addcap, list_node_new(cap_name));
                    }
                    else if(strncmp(p,"-",1)==0)
                    {
                        char * cap_name = &p[1];
                        syslog(LOG_INFO, "pam-login-cap:对特权进程删除权能:%s没有意义,不执行任何操作",cap_name);
                        // list_rpush(process_delcap, list_node_new(cap_name));
                    }
                    else
                        syslog(LOG_ERR, "pam-login-cap:权能配置错误:%s",p);
                }

                list_rpush(cap_list, list_node_new(cap));
                change_caps(cap);
            }
            else
                syslog(LOG_ERR, "pam-login-cap:权能配置错误-错误的配置:%s",p);
            
        }
	}
    if(pam_set_data(pamh, "cap_list", cap_list, NULL))
        syslog(LOG_ERR,"pam-login-cap:pamh数据设置失败 ERROR:%d,%s",errno,strerror(errno));

    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    syslog(LOG_INFO, "pam-login-cap:退出会话");

    //根据配置恢复权能
    list_t * cap_list = NULL;
    pam_get_data(pamh, "cap_list", (const void **)&cap_list);
    list_iterator_t *it = list_iterator_new(cap_list, LIST_HEAD);
    list_node_t *node;
    while((node = list_iterator_next(it))) {
        cap_list_t * cap = node->val;
        if(cap ->filename!=NULL)
        {
            syslog(LOG_INFO, "pam-login-cap:取消权能修改，目标文件:%s",cap->filename);


            list_node_t *cap_node;
            list_iterator_t *it_add = list_iterator_new(cap->addcap_list, LIST_HEAD);
            while((cap_node = list_iterator_next(it_add))) {
                char * cap_name = cap_node->val;
                syslog(LOG_INFO, "pam-login-cap:取消增加权能:%s",cap_name);
            }
            list_iterator_destroy(it_add);
            

            list_iterator_t *it_del = list_iterator_new(cap->delcap_list, LIST_HEAD);
            while((cap_node = list_iterator_next(it_del))) {
                char * cap_name = cap_node->val;
                syslog(LOG_INFO, "pam-login-cap:取消删除权能:%s",cap_name);
            }
            list_iterator_destroy(it_del);
        }
        else{
            // 进程自动死亡，不需要恢复权能
            ;//do nothing
        }

        undo_change_caps(cap);

        list_destroy(cap->addcap_list);
        list_destroy(cap->delcap_list);

    }
    if(it != NULL)
        list_iterator_destroy(it);
    list_destroy(cap_list);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    syslog(LOG_INFO, "pam-login-cap:进入凭证修改服务");
    syslog(LOG_ERR,"pam-login-cap:凭证修改服务：这一服务不应被调用");
    return PAM_SERVICE_ERR;
}