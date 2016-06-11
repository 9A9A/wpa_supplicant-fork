#include "wpa_roam.h"
#include "wpa_application.h"
using namespace std;
using namespace chrono;


void signal_handler(int signum)
{
    if(Application::locker()->locked())
    {
        Application::locker()->unlock();
    }
    else
    {
        exit(0);
    }
}


int main(int argc,char* argv[])
{
#ifdef DEBUG
    SetThreadName("MainThread");
#endif
    try
    {
        int default_rssi = DEFAULT_RSSI_LEVEL;
        int default_diff = DEFAULT_DIFF;
        const char* iface_name = nullptr;
        const char* unix_socket_dir = nullptr;
        string param;
        int scan_treshold = default_rssi;
        int difference = default_diff;
        int minrssi = default_rssi;
        int transition_time = default_diff;
        string str_t;
        int c;
        while(true)
        {
            c = getopt(argc,argv,"p:i:t:s:m:h:");
            if(c<0)
            {
                break;
            }
            switch(c)
            {
            case 'i':
                iface_name = optarg;
                break;
            case 'p':
                unix_socket_dir = optarg;
                break;
            case 's':
                param = optarg;
                scan_treshold = stoi(param);
                break;
            case 't':
                param = optarg;
                transition_time = stoi(param);
                break;
            case 'm':
                param = optarg;
                minrssi = stoi(param);
                break;
            case 'h':
                param = optarg;
                difference = stoi(param);
                break;
            default:
                Application::usage();
                return -1;
            }
        }
        if((scan_treshold == default_rssi) || (difference == default_diff) || (minrssi == default_rssi) || (transition_time == default_diff))
        {
            Application::usage();
        }
        else if(iface_name)
        {
            string path;
            if(unix_socket_dir)
            {
                path = unix_socket_dir;
            }
            else
            {
                path = DEFAULT_DIR;
            }
            signal(SIGINT,signal_handler);
            signal(SIGTERM,signal_handler);
            signal(SIGHUP,signal_handler);
            Application app(path,iface_name,difference,transition_time,scan_treshold,minrssi);
            Application::locker()->lock();
        }
        else
        {
            Application::usage();
            printf("Control interface isn't specified\n");
        }
    }
    catch(runtime_error& err)
    {
        Application::locker()->unlock();
        cout << err.what() << endl;
    }
}
