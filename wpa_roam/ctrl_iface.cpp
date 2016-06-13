#include "wpa_roam.h"

using namespace std;
using namespace chrono;

wpa_ctrl_iface::wpa_ctrl_iface(const string& unix_socket_dir , const string& iface)
{
    m_bAttached = false;
    m_bConnected = false;
    m_bThreadActive = false;
    m_ctrl_iface_dir = unix_socket_dir;
    m_ctrl_iface_name = iface;
    if(!m_ctrl_iface_dir.empty() && !m_ctrl_iface_name.empty())
    {
        if(m_ctrl_iface_dir.back()!='/')
        {
            m_ctrl_iface_dir.push_back('/');
        }
        if(connect())
        {
            if(!attach())
            {
                throw runtime_error("wpa_ctrl_iface : can't attach to wpa_supplicant");
            }
        }
        else
        {
            throw runtime_error("wpa_ctrl_iface : can't connect to wpa_supplicant");
        }
    }
}

wpa_ctrl_iface::~wpa_ctrl_iface()
{
    disconnect();
#ifdef DEBUG
    cout << CurrentTime() << __CLASS__ << " destroyed\n";
#endif
}

bool wpa_ctrl_iface::is_connected() const
{
    return m_bConnected;
}
bool wpa_ctrl_iface::is_attached() const
{
    return m_bAttached;
}
string wpa_ctrl_iface::get_iface_dir() const
{
    return m_ctrl_iface_dir;
}
string wpa_ctrl_iface::get_iface_name() const
{
    return m_ctrl_iface_name;
}
bool wpa_ctrl_iface::connect()
{
    lock_guard<recursive_mutex> lock(m_locker);
    if(!m_bConnected)
    {
        auto check_exist=[](const string& name)->bool
        {
            struct stat buffer;
            return (stat(name.c_str(),&buffer)==0);
        };
        auto path = m_ctrl_iface_dir + m_ctrl_iface_name;
        cout << CurrentTime()  << "Waiting for wpa_supplicant\n";
        while(true)
        {
            if(check_exist(path))
            {
                break;
            }
            THREAD_WAIT(ACTIVE_SCAN_DELAY);
        }
        if(check_exist(path))
        {
            m_pwpa_ctrl_iface = wpa_ctrl_open(path.data());
            if(m_pwpa_ctrl_iface)
            {
                m_bConnected = true;
                return true;
            }
            else
            {
                return false;
            }
        }
        else
        {
            throw runtime_error("wpa_ctrl_iface::connect() : specified iface : " + path + " doesn't exist");
        }
    }
    else
    {
        return false;
    }
}
bool wpa_ctrl_iface::attach()
{
    lock_guard<recursive_mutex> lock(m_locker);
    if(m_bConnected && !m_bAttached)
    {
        int result_t = wpa_ctrl_attach(m_pwpa_ctrl_iface);
        switch(result_t)
        {
            case 0:
                m_bAttached = true;
                start_thread();
                return true;
            default:
                return false;
        }

    }
    else
    {
        return false;
    }
}
wpa_response wpa_ctrl_iface::request(const string& cmd, size_t response_size)
{
    if(m_bConnected)
    {
        lock_guard<recursive_mutex> lock(m_locker);
        wpa_response response_t(response_size);
        wpa_ctrl_request(m_pwpa_ctrl_iface,cmd.data(),cmd.size(),response_t.data(),response_t.size(),nullptr);
        return response_t;
    }
    else
    {
        throw runtime_error("wpa_ctrl_iface::request : has no connection to wpa_supplicant to make requests");
    }
}
bool wpa_ctrl_iface::detach()
{
    lock_guard<recursive_mutex> lock(m_locker);
    if(m_bConnected && m_bAttached)
    {
        int result_t = wpa_ctrl_detach(m_pwpa_ctrl_iface);
        stop_thread();
        switch(result_t)
        {
            case 0:
                m_bAttached = false;
                return true;
            default:
                return false;
        }
    }
    else
    {
        return false;
    }
}
bool wpa_ctrl_iface::disconnect()
{
    lock_guard<recursive_mutex> lock(m_locker);
    if(m_bAttached)
    {
        detach();
        if(m_bConnected)
        {
            wpa_ctrl_close(m_pwpa_ctrl_iface);
            m_bConnected = false;
            return true;
        }
        return false;
    }
    return false;
}
void wpa_ctrl_iface::start_thread()
{
    if(m_bConnected && m_bAttached)
    {
        m_bThreadActive = true;
        m_pthread = make_unique<thread>([this]{thread_routine();});
    }
}
void wpa_ctrl_iface::stop_thread()
{
    if(m_bThreadActive)
    {
        m_bThreadActive = false;
        if(m_pthread)
        {
            m_pthread->join();
        }
    }
}
void wpa_ctrl_iface::thread_routine()
{
#ifdef DEBUG
    ThrdInf thr("CtrlIfaceThread");
#endif
    while(m_bThreadActive)
    {
        if(wpa_ctrl_pending(m_pwpa_ctrl_iface))
        {
            if(OnMessageReceived)
            {
                lock_guard<recursive_mutex> lock(m_locker);
                wpa_response response_t(DEFAULT_MSG_SIZE);
                if(wpa_ctrl_recv(m_pwpa_ctrl_iface,response_t.data(),response_t.size()) == 0)
                {
                    OnMessageReceived(response_t);
                }
                else if (wpa_ctrl_recv(m_pwpa_ctrl_iface,response_t.data(),response_t.size()) == -1)
                {
                    cout << CurrentTime() << "Error occured : ctrl_iface\n";
                }
//                cout << "Thread iface_loop :: unlocked : " << thread_id() << endl;
            }
        }
        else
        {
            THREAD_WAIT(THREAD_SLEEP_DELAY);
        }
    }
}

