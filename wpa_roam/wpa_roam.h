#ifndef WPA_ROAM_H_INCLUDED
#define WPA_ROAM_H_INCLUDED
#define CONFIG_CTRL_IFACE_UNIX
#include <iostream>
#include <cstring>
#include <sstream>
#include <fstream>
#include <vector>
#include <stdio.h>
#include <sys/stat.h>
#include <functional>
#include <memory>
#include <thread>
#include <chrono>
#include <algorithm>
#include <map>
#include <ctime>
#include <condition_variable>
#include <atomic>
#include <mutex>
#include <set>
#include <string>
#include <unistd.h>
#include "common/wpa_ctrl.h"



#define PING "PING"
#define STATUS_VERBOSE "STATUS-VERBOSE"
#define STATUS "STATUS"
#define SCAN "SCAN"
#define SCAN_RESULTS "SCAN_RESULTS"
#define TERMINATE "TERMINATE"
#define REASSOCIATE "REASSOCIATE"
#define DISCONNECT "DISCONNECT"
#define BSS "BSS"
#define ROAM "ROAM"
#define RECONNECT "RECONNECT"
#define BSSID "BSSID"
#define LIST_NETWORKS "LIST_NETWORKS"
#define WPA_EVENT_ASSOCIATED "Associated with "
#define PASSIVE_SCAN_REQUEST "SCAN passive=1"
#define SCAN_FREQUENCY "SCAN freq=<"
#define FREQ " freq="
#define PASSIVE " passive=1 "

#define DEFAULT_RSSI_LEVEL 100
#define DEFAULT_DIFF -1

#define BASE_2_4GHZ_FREQ 2412
#define FREQ_OFFSET 5
#define END_2_4GHZ_FREQ 2472


#define PASSIVE_SCAN_CHANNEL_DELAY 500
#define ACTIVE_SCAN_DELAY 250
#define PASSIVE_SCAN_DELAY 1250


#define CONNECTED_STATE "wpa_state=COMPLETED"
#define DISCONNECTED_STATE "wpa_state=DISCONNECTED"
#define THREAD_SLEEP_DELAY 10 // delay socket polling 100 Hz by default
#define APP_THREAD_WAIT 100
#define WPA_SUPPLICANT_WAIT 250


#define DEFAULT_DIR "/var/run/wpa_supplicant"
#define DEFAULT_MSG_SIZE 4096
#define MAX_MAC_ADDR_SIZE 17
#define MAX_MAC_ADDR_LENGTH 6
#define MAX_MAC_ADDR_DELIMS 5
#define THREAD_WAIT(x)  this_thread::sleep_for(milliseconds(x))

using namespace std;
using namespace chrono;
typedef unsigned char byte;
string CurrentTime (bool flag = false );
#ifdef DEBUG
class ThreadInfo
{
    map<thread::id,string> m_threadid;
    recursive_mutex m_locker;
    ThreadInfo();
    ~ThreadInfo();
public:
    ThreadInfo(const ThreadInfo& ) = delete;
    ThreadInfo(ThreadInfo&& ) = delete;
    ThreadInfo& operator = (const ThreadInfo& ) = delete;
    ThreadInfo& operator = (ThreadInfo&& ) = delete;
    static ThreadInfo& instance();
    void SetThreadName(const string& str);
    void EraseThreadName();
    string ThreadId();
};
class ThrdInf
{
public:
    ThrdInf() = delete;
    ThrdInf(const string& thread_name);
    ThrdInf(const ThrdInf& ) = delete;
    ThrdInf(ThrdInf&& ) = delete;
    ThrdInf& operator = (const ThrdInf& ) = delete;
    ThrdInf& operator = (ThrdInf&& ) = delete;
    ~ThrdInf();
};
#define LOG_INTERVAL 250
#define __CLASS__ ThreadInfo::instance().ThreadId() + "#" + typeid(*this).name()
#endif
class wpa_response
{
public:
    wpa_response(size_t size);
    wpa_response(const wpa_response& obj);
    friend ostream& operator<<(ostream& os, wpa_response& obj);
    friend ostream& operator<<(ostream& os, wpa_response obj);
    string to_string() const;
    bool empty() const;
    char* data();
    size_t* size();
    virtual ~wpa_response();
private:
    bool m_bempty;
    char* m_pmsg;
    size_t m_nsize;
};
class mac_addr
{
public:
    mac_addr();
    mac_addr(const string& addr);
    mac_addr(byte b1,byte b2,byte b3,byte b4,byte b5, byte b6);
    mac_addr(const mac_addr& obj);
    mac_addr& operator = (const mac_addr& obj);
    mac_addr& operator = (const string& str);
    bool empty() const;
    bool operator == (const mac_addr& obj) const;
    bool operator != (const mac_addr& obj) const;
    friend ostream& operator << (ostream& os,const mac_addr& mac);
    byte* data();
    string to_string() const;
private:
    byte m_addr[MAX_MAC_ADDR_LENGTH];
};
class wpa_ctrl_iface
{
public:
    wpa_ctrl_iface() = delete;
    wpa_ctrl_iface(const string& unix_socket_dir , const string& iface);

    virtual ~wpa_ctrl_iface();

    bool is_connected() const;
    bool is_attached() const;
    string get_iface_dir() const;
    string get_iface_name() const;
    bool connect();
    bool attach();
    wpa_response request(const string& cmd, size_t response_size = DEFAULT_MSG_SIZE);
    bool detach();
    bool disconnect();
    //works only in attached mode
    function<void(wpa_response& )> OnMessageReceived;

private:
    void start_thread();
    void stop_thread();
    void thread_routine();

//    mutex m_locker;
    recursive_mutex m_locker;
    string m_ctrl_iface_dir;
    string m_ctrl_iface_name;

    struct wpa_ctrl* m_pwpa_ctrl_iface;

    atomic<bool> m_bConnected;
    atomic<bool> m_bAttached;

    unique_ptr<thread> m_pthread;
    atomic<bool> m_bThreadActive;

};
class wpa_event_monitor
{
public:
    wpa_event_monitor(shared_ptr<wpa_ctrl_iface>& iface);
    virtual ~wpa_event_monitor();
    shared_ptr<wpa_ctrl_iface>& iface();

    typedef function<void()> EVENT;
    typedef function<void(mac_addr&)> EVENT_P;
    EVENT    OnEventTerminating;
    EVENT_P  OnEventConnected;
    EVENT_P  OnEventDisconnected;
    EVENT_P  OnEventAssociating;
    EVENT    OnEventScanStarted;
    EVENT    OnEventScanResultsAvailable;
    EVENT_P  OnEventBSSAdded;
    EVENT_P  OnEventBSSRemoved;
private:
    void parser(wpa_response& response);
    shared_ptr<wpa_ctrl_iface> m_pwpa_ctrl_iface;
};
class wpa_access_point
{
public:
    wpa_access_point();
    wpa_access_point(const wpa_access_point& obj);
    wpa_access_point(bool os,const string& ssid,const mac_addr& addr,size_t freq,int rssi);
    wpa_access_point& operator =(const wpa_access_point& obj);
    const string& ssid() const;
    int rssi() const;
    int frequency() const;
    void cancel_hysteresis();
    void start_hysteresis(int new_rssi,int hyst_difference_rssi);
    bool check_hysteresis(int new_rssi,int hyst_difference_rssi,int minrssi, std::chrono::seconds& transition_time);
    bool is_hysteresis() const;
    bool is_open() const;
    const mac_addr& bssid() const;
    void set_open(bool flag);
    void set_frequency(size_t frequency);
    void set_ssid(const string& ssid);
    void set_rssi(int rssi);
    void set_bssid(mac_addr& addr);
    friend ostream& operator<<(ostream& os,const wpa_access_point& ap);
    bool operator < (const wpa_access_point& ap);
    bool operator > (const wpa_access_point& ap);
    bool operator == (const wpa_access_point& ap);
    bool operator != (const wpa_access_point& ap);
private:
    mutex m_locker;
    bool m_bHysteresisMode;
    std::chrono::seconds m_HysteresisStartTime;
    bool m_bopen_system;
    string m_ssid;
    size_t m_frequency;
    mac_addr m_bssid;
    int m_rssi;
};
class ap_list
{
private:
    mutex m_locker;
    vector<wpa_access_point> m_ap_list;
public:
    ap_list();
    ap_list(wpa_access_point& ap);
    ap_list(const ap_list& obj);
    virtual ~ap_list();
    auto begin() -> decltype(m_ap_list.begin());
    auto begin() const -> decltype(m_ap_list.begin());
    auto end() -> decltype(m_ap_list.end());
    auto end() const -> decltype(m_ap_list.end());
    size_t size() const;
    const vector<wpa_access_point> data() const;
    ap_list get_all_by_ssid(const string& ssid);
    wpa_access_point* find_ap_by_bssid(const mac_addr& bssid);
    wpa_access_point* get_best_signal(mac_addr& bssid);
    wpa_access_point* get_best_signal(const string& ssid);
    void push_back(const wpa_access_point& ap);
    void remove_all_exclude(const string& ssid);
    void remove(const string& ssid);
    void remove(mac_addr& addr);
    void sort();
    wpa_access_point& operator [] (size_t pos);
};


class wpa_roamer
{
public:
    wpa_roamer(shared_ptr<wpa_event_monitor>& monitor,size_t Hysteresis,size_t TransitionTime,int ScanThreshold,int MinRssi );
    virtual ~wpa_roamer();
    shared_ptr<wpa_ctrl_iface>& iface();

private:
    void unbind_callbacks();
    void OnAssociating(mac_addr& addr);
    void OnBSSAdded(mac_addr& addr);
    void OnBSSRemoved(mac_addr& addr);
    void OnDisconnected(mac_addr& addr);
    void OnConnected(mac_addr& addr);
    void OnScanStarted();
    void OnScanResults();
    void OnTerminating();
    void make_roam(const string& _ssid,const mac_addr& _bssid);
    void hard_roam(ap_list* ptr);
    void soft_roam(ap_list* ptr);
    void unlock_polling_thread();
    void update_connection_state();
    void start_thread();
    void stop_thread();
    int get_network_id(const string& ssid);
    void thread_routine();
    void active_scanning();
    void passive_scanning(size_t freq = 0);
    void show_list(ap_list* ptr);
    void cancel_hysteresis(ap_list* ptr);
    void parse_scan_request(wpa_response& resp);


    bool m_bShutdownMode;
    bool m_bDebug;
    size_t m_nHysteresis;
    seconds m_nTransitionTime;
    int m_nScanThresholdLevel;
    int m_nMinRssiLevel;
    int m_current_rssi;

    mutex m_locker;
    mutex m_synchronized;
    condition_variable m_changed;
    atomic<bool> m_bNotified;
    atomic<bool> m_bInActiveMode;
    atomic<bool> m_bThreadActive;
    unique_ptr<thread> m_pthread;
    //network params
    ap_list m_scanned_ap_list;
    mac_addr m_current_bssid;
    string m_ssid;
    atomic<bool> m_bConnected;
#ifdef DEBUG
    friend class logger;
#endif
    shared_ptr<wpa_event_monitor> m_pevent_mon;
};
#ifdef DEBUG
class logger
{
public:
    logger(shared_ptr<wpa_roamer>& roamer,int log_period);
    virtual ~logger();
private:
    void thread_routine();
    int m_period;
    unique_ptr<fstream> m_pFileHandle;
    shared_ptr<wpa_roamer> m_pRoamer;
    atomic<bool> m_bActive;
    unique_ptr<thread> m_pthread;
};
#endif
#endif // WPA_ROAM_H_INCLUDED
