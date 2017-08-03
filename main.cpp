#include <iostream>

#include "Pinger.h"

using namespace std;

int main()
{
    cout << "Hello World!" << endl;
    for(int i=0;i<10;i++){
        Pinger p;
        p.ping("192.168.1.1",1,200,200);
        cout<<p.getTips().c_str()<<endl;
    }
    return 0;
}
