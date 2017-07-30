#include <iostream>

#include "Pinger.h"

using namespace std;

int main()
{
    cout << "Hello World!" << endl;
    Pinger p;
    p.ping("192.168.1.1",2,200,200);
    cout<<p.getTips().c_str()<<endl;
    return 0;
}
