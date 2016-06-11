#ifndef WPA_APPLICATION_H_INCLUDED
#define WPA_APPLICATION_H_INCLUDED
#include "wpa_roam.h"
#include "signal.h"

class g_MainThreadLock
{
    mutex m_lock;
    condition_variable m_condvar;
    atomic<bool> m_bLocked;
public:
    g_MainThreadLock();
    void lock();
    void unlock();
    bool locked();
};
class Application
{
    shared_ptr<wpa_ctrl_iface> m_pIface;
    shared_ptr<wpa_event_monitor> m_pmonitor;
    shared_ptr<wpa_roamer> m_proamer;
#ifdef DEBUG
    shared_ptr<logger> m_plogger;
#endif
public:
    Application(const string&   unix_socket,
                const string&   iface,
                size_t          hysteresis,
                size_t          transition_time,
                int             scan_threshold,
                int             min_rssi);
    static g_MainThreadLock* locker();
    static void usage();
};
#endif // WPA_APPLICATION_H_INCLUDED
