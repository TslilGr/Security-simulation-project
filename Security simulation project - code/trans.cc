#include <stdio.h>
#include <string.h>
#include <omnetpp.h>
#include <iostream>
#include <stdlib.h>
#include "message_m.h"


using namespace omnetpp;
using namespace std;

typedef struct groups{
   int grp_index;
   string ip;
   int members;
   int count_type[3];
   double score;
   double py;
   double pxi;
   groups* next;
}groups;


class  Traffic : public cSimpleModule{
private:
        int type=0;//0- normal; 1-dDos 2-Flash crowd
        int count_host_nor=0;
        int count_host_dos=0;
        int count_host_flash=0;
        int count_msg=0;
        string ip;

    protected:
        virtual void initialize() override;
        virtual void handleMessage(cMessage *msg) override;
        string insert_ip(int oct,string ip);
        string generat_ip(int type);
};

Define_Module(Traffic);

void Traffic::initialize(){
    ip=generat_ip(0);
    Msg* msg=new Msg;
    scheduleAt(0.0,msg);
}

void Traffic::handleMessage(cMessage *msg){
   // delete(msg);
    int random=0;//counters for number of host
    Msg *new_msg=new Msg("new_msg");
    if(count_host_nor<(int)this->par("nor_host")){//sending normal messages
        random= rand() % 3;
        new_msg->setIp(ip.c_str());
        new_msg->setType(type);
        if(count_msg<=7+random){//sending around 8 messages
           send(new_msg, "out");
           count_msg=count_msg+1;
           scheduleAt(0.05+simTime(),msg);
       }else{
           ip=generat_ip(0);
           count_msg=0;
           count_host_nor=count_host_nor+1;
           if(count_host_nor==(int)this->par("nor_host"))
               ip=generat_ip(1);
           scheduleAt(0.05+simTime(),msg);
       }
    }else{
        if(count_host_dos<(int)this->par("dos_host")){//sending normal messages
            random= rand() % 7;
            new_msg->setIp(ip.c_str());
            new_msg->setType(type);
            if(count_msg<=50+random){//sending around 53 messages
               send(new_msg, "out");
               count_msg=count_msg+1;
               scheduleAt(0.05+simTime(),msg);
           }else{
               ip=generat_ip(1);
               count_msg=0;
               count_host_dos=count_host_dos+1;
               if(count_host_dos==(int)this->par("dos_host"))
                   ip=generat_ip(2);
               scheduleAt(0.05+simTime(),msg);
           }
        }
        else{
           if(count_host_flash<(int)this->par("flash_host")){//sending normal messages
              random= rand() % 4;
              new_msg->setIp(ip.c_str());
              new_msg->setType(type);
              if(count_msg<=20+random){//sending around 22 messages
                 EV<<"sending message 2 with ip:"<<ip.c_str() <<endl;
                 send(new_msg, "out");
                 count_msg=count_msg+1;
                 scheduleAt(0.05+simTime(),msg);
             }else{
                 ip=generat_ip(2);
                 count_msg=0;
                 count_host_flash=count_host_flash+1;
                 scheduleAt(0.05+simTime(),msg);
             }
           }
        }
    }
}



string Traffic:: generat_ip(int type){
    string temp;
    if (type==0) {
           //generate randomly the last octat
            temp="192.168.072.";
            temp=insert_ip(3,temp);
        }
    else if(type==1){    //generate randomly the two last octats
            temp="192.168.";
            temp=insert_ip(2,temp);
            temp=insert_ip(3,temp);

        }
    else if(type==2){//generate randomly all octats
            temp="";
            temp=insert_ip(0,temp);
            temp=insert_ip(1,temp);
            temp=insert_ip(2,temp);
            temp=insert_ip(3,temp);
        }
    else{
            temp="192.168.072.";
            temp=insert_ip(3,temp);
        }

    return temp;
}

string Traffic:: insert_ip(int oct,string ip){// string the ip
    char random1,random2,random3;
    random1 = rand()%3 + 48;
    if(random1==50){
        random2=rand()%6 + 48;
        if(random2==53){
            random3=rand()%6 + 48;
        }
        else
            random3=rand()%10 + 48;
    }
    else{
        random2=rand()%10 + 48;
        random3=rand()%10 + 48;
    }
    ip.push_back(random1);
    ip.push_back(random2);
    ip.push_back(random3);
    if(oct!=3)
        ip.push_back('.');
    return ip;
}




class Target : public cSimpleModule{
private:
    groups* grp;
    int msg_count;
    double sys_entropy;
protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish()override;
    int convert_ip(string ip,int start,int end);
    double calc_entropy();
    void calc_score();
    bool search_group(int oct1,int oct2,int oct3,int oct4,groups* temp);
};

Define_Module(Target);

void Target:: initialize(){
    grp=new groups;
    grp->ip="192.168.072.000";
    grp->grp_index=0;
    grp->score=0.0;
    grp->members=0;
    for(int i=0;i<3;i++)
        grp->count_type[i]=0;
    msg_count=0;
    grp->next=NULL;
    sys_entropy=0;
    grp->py=1;
    grp->pxi=0;
    Entropy *new_enp_msg=new Entropy("new_enp_msg");
    scheduleAt(30.001+simTime(), new_enp_msg);
}


void Target ::handleMessage(cMessage *msg){
    if(msg->isSelfMessage()){//Receive entropy message
        sys_entropy=calc_entropy();
        EV<<"Calculated entropy:"<<sys_entropy<<endl;
       // Entropy *new_enp_msg=new Entropy("new_enp_msg");
        if(sys_entropy<(double)this->par("thresh_entropy")){
         //   calc_score();
        }
        else{
           // calc_score();
            groups* temp=grp;
            while(temp->next!=NULL){
                if(temp->score < (double)this->par("thresh_score")){
                    EV<<"FLASH CROWD ATTACK DETECTED in group: "<<temp->grp_index<<endl;
                    finish();
                }else if(temp->score > (double)this->par("thresh_score")){
                    EV<<"DDoS ATTACK DETECTED in group: "<<temp->grp_index<<endl;
                    finish();
                }
                else
                    temp=temp->next;
            }
        }
        scheduleAt(30.001+simTime(),msg);

    }
    else{
        bool flag=false;//no group found
        string ip=((Msg*)msg)->getIp();
        int type=((Msg*)msg)->getType();
        int oct1=convert_ip(ip,0,2);
        int oct2=convert_ip(ip,4,6);
        int oct3=convert_ip(ip,8,10);
        int oct4=convert_ip(ip,12,14);
        groups* temp=grp;
        msg_count=msg_count+1;

        while(temp->next!=NULL && flag==false){//search for group
            flag=search_group(oct1, oct2, oct3, oct4, temp);
            if(flag==false)
                temp=temp->next;

        }//end while
        flag=search_group(oct1, oct2, oct3, oct4, temp);
        if(flag==false){//create new group
            groups* new_grp=new groups;
            new_grp->grp_index=temp->grp_index+1;
            new_grp->ip=ip;
            new_grp->members=1;
            new_grp->next=NULL;
            new_grp->score=1/msg_count;/////////???????????
            temp->next=new_grp;
            EV << "new group created"<< "  grp_index= " << temp->grp_index<<"ip" <<ip<<endl;
        }
    }
}

bool Target ::search_group(int oct1,int oct2,int oct3,int oct4,groups* temp){

    if(oct1==convert_ip(temp->ip,0,2)){
        if(oct2==convert_ip(temp->ip,4,6)){
            if(oct3==convert_ip(temp->ip,8,10)){
                if(abs(oct4-convert_ip(temp->ip,12,14))<(int)this->par("distance")){
                    temp->members=temp->members+1;
                    return true;
                    ///do analizis part
                }
                else{
                    return false;
                }
            }else{
                return false;
            }
        }else{
            return false;
        }
    }else
        return false;

}

int Target:: convert_ip(string ip,int start,int end){

    int oct=0;
    oct=(int)ip[end]-48;
    oct= oct+((int)ip[start+1]-48)*10;
    oct=oct+((int)ip[start]-48)*100;

return oct;
}

double Target::calc_entropy(){
    groups * temp=grp;
    int mem=0;
    long double sum=0, curr=0;
    EV<<"msg"<<msg_count<<"members:"<<temp->members<<endl;
    while(temp->next!=NULL){
        mem=temp->members;
        EV<<"msg"<<msg_count<<"members:"<<temp->members<<endl;
        if(temp->members==0){
            temp=temp->next;
        }else{
            temp->pxi=(double)mem/(double)msg_count;
            curr=temp->pxi;
            sum=sum+curr*(curr);
            temp=temp->next;
        }
    }
    temp->pxi=((double)temp->members/(double)msg_count);
    sum=sum+(temp->pxi*log2(temp->pxi));
    sum=sum*(-1);
    return sum;
}



void Target::calc_score(){
    double score;
    groups* temp=grp;
    while(temp->next!=NULL){
        score=temp->pxi/temp->py;
        temp->score=score;
        temp->py=temp->pxi;
        temp=temp->next;
    }
    score=temp->pxi/temp->py;
    temp->score=score;
    temp->py=temp->pxi;
}

void Target :: finish(){

}











