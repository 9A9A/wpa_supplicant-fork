#include "wpa_application.h"

g_MainThreadLock::g_MainThreadLock()
{
    m_bLocked = false;
}
void g_MainThreadLock::lock()
{
    m_bLocked = true;
    while(m_bLocked)
    {
        unique_lock<mutex> locker(m_lock);
        m_condvar.wait(locker);
    }
}
void g_MainThreadLock::unlock()
{
    m_bLocked = false;
    m_condvar.notify_all();
}

Application::Application(const string&   unix_socket,
            const string&   iface,
            size_t          hysteresis,
            size_t          transition_time,
            int             scan_threshold,
            int             min_rssi)
{
    m_pIface = make_shared<wpa_ctrl_iface>(unix_socket,iface);
    m_pmonitor = make_shared<wpa_event_monitor>(m_pIface);
    m_proamer = make_shared<wpa_roamer>(m_pmonitor,hysteresis,transition_time,scan_threshold,min_rssi);
#ifdef DEBUG
    m_plogger = make_shared<logger>(m_proamer,LOG_INTERVAL);
#endif
}
void Application::usage()
{
    printf("wpa_roam [-p<path to ctrl sockets>] [-i<ifname>]\n"
            "[-h<hysteresis>] [-s<scan threshold>] [-t<transition time>] [-m<min rssi>]\n"
            "-t = must be positive\n"
            "-s = must be negative\n"
            "-h = must be positive\n"
            "-m = must be negative\n"
             "default path : " DEFAULT_DIR "\n");
}
g_MainThreadLock* Application::locker()
{
    static g_MainThreadLock main_thread_lock;
    return &main_thread_lock;
}
