#include "wpa_roam.h"
//WPA_ACCESS_POINT CLASS
wpa_access_point::wpa_access_point()
{
    m_bHysteresisMode = false;
}
wpa_access_point::wpa_access_point(bool os,const string& ssid,mac_addr& addr,size_t freq,int rssi)
{
    m_bopen_system = os;
    m_ssid = ssid;
    m_bssid = addr;
    m_frequency = freq;
    m_rssi = rssi;
    m_bHysteresisMode = false;
}
wpa_access_point& wpa_access_point::operator =(const wpa_access_point& obj)
{
    if(this!=&obj)
    {
        m_bopen_system = obj.m_bopen_system;
        m_ssid = obj.m_ssid;
        m_bssid = obj.m_bssid;
        m_frequency = obj.m_frequency;
        m_rssi = obj.m_rssi;
        m_bHysteresisMode = obj.m_bHysteresisMode;
        m_HysteresisStartTime = obj.m_HysteresisStartTime;
    }
    return *this;
}
const string& wpa_access_point::ssid() const
{
    return m_ssid;
}
int wpa_access_point::rssi() const
{
    return m_rssi;
}
int wpa_access_point::frequency() const
{
    return m_frequency;
}
void wpa_access_point::cancel_hysteresis()
{
    if(m_bHysteresisMode)
    {
#ifdef DEBUG
        cout << "Cancel hysteresis : " << m_bssid.to_string() << endl;
#endif
        m_bHysteresisMode = false;
    }
}
void wpa_access_point::start_hysteresis(int new_rssi,int hyst_difference_rssi)
{
    if(!m_bHysteresisMode)
    {
        if(abs(m_rssi - new_rssi) >= hyst_difference_rssi)
        {
#ifdef DEBUG
            cout << "Start Hysteresis : " << m_bssid.to_string() << endl;
#endif
            m_bHysteresisMode = true;
            m_HysteresisStartTime = duration_cast<seconds>(system_clock::now().time_since_epoch());
        }
    }
}
bool wpa_access_point::check_hysteresis(int new_rssi,int hyst_difference_rssi,int minrssi, std::chrono::seconds& transition_time)
{
    if(m_bHysteresisMode)
    {
        if(abs(m_rssi - new_rssi) >= hyst_difference_rssi && new_rssi  > minrssi && m_rssi > new_rssi) // patch
        {
            auto current_time = duration_cast<seconds>(system_clock::now().time_since_epoch());
            if(current_time.count() - m_HysteresisStartTime.count() >= transition_time.count())
            {
                cancel_hysteresis();
                cout << "[" << m_HysteresisStartTime.count() << "-" << current_time.count() << "]\n";
                return true;
            }
            else
            {
                return false;
            }
        }
        else
        {
            cancel_hysteresis();
            return false;
        }
    }
    else
    {
        return false;
    }
}
bool wpa_access_point::is_hysteresis() const
{
    return m_bHysteresisMode;
}
bool wpa_access_point::is_open() const
{
    return m_bopen_system;
}
const mac_addr& wpa_access_point::bssid() const
{
    return m_bssid;
}
void wpa_access_point::set_open(bool flag)
{
    m_bopen_system = flag;
}
void wpa_access_point::set_frequency(size_t frequency)
{
    m_frequency = frequency;
}
void wpa_access_point::set_ssid(const string& ssid)
{
    m_ssid = ssid;
}
void wpa_access_point::set_rssi(int rssi)
{
    m_rssi = rssi;
}
void wpa_access_point::set_bssid(mac_addr& addr)
{
    m_bssid = addr;
}

// APLIST CLASS

ap_list::ap_list()
{
}
ap_list::ap_list(wpa_access_point& ap)
{
    push_back(ap);
}
ap_list::ap_list(const ap_list& obj)
{
    m_ap_list = obj.m_ap_list;
}
ap_list::~ap_list()
{
    m_ap_list.clear();
}
auto ap_list::begin() -> decltype(m_ap_list.begin())
{
    lock_guard<mutex> lck(m_locker);
    return m_ap_list.begin();
}
auto ap_list::begin() const -> decltype(m_ap_list.begin())
{
    return m_ap_list.begin();
}
auto ap_list::end() -> decltype(m_ap_list.end())
{
    lock_guard<mutex> lck(m_locker);
    return m_ap_list.end();
}
auto ap_list::end() const -> decltype(m_ap_list.end())
{
    return m_ap_list.end();
}
size_t ap_list::size() const
{
    return m_ap_list.size();
}
const vector<wpa_access_point> ap_list::data() const
{
    return m_ap_list;
}
ap_list ap_list::get_all_by_ssid(const string& ssid)
{
    lock_guard<mutex> lck(m_locker);
    ap_list ap_ls;
    for(auto &i : m_ap_list)
    {
        if(i.ssid() == ssid)
        {
            ap_ls.push_back(i);
        }
    }
    return ap_ls;
}
wpa_access_point* ap_list::find_ap_by_bssid(const mac_addr& bssid)
{
    lock_guard<mutex> lck(m_locker);
    for(auto &i : m_ap_list)
    {
        if(i.bssid()== bssid)
        {
            return &i;
        }
    }
    return nullptr;
}
wpa_access_point* ap_list::get_best_signal(mac_addr& bssid) // call only if 1 or more ap available
{
    lock_guard<mutex> lck(m_locker);
    size_t id;
    int signal = -200;
    for(size_t i=0;i<m_ap_list.size();i++)
    {
        if(m_ap_list[i].bssid() != bssid && signal < m_ap_list[i].rssi())
        {
            signal = m_ap_list[i].rssi();
            id = i;
        }
    }
    return &m_ap_list[id];
}
wpa_access_point* ap_list::get_best_signal(const string& ssid)
{
    lock_guard<mutex> lck(m_locker);
    int id=-500;
    int signal = -200;
    for(size_t i=0;i<m_ap_list.size();i++)
    {
        if(m_ap_list[i].ssid() == ssid && signal < m_ap_list[i].rssi())
        {
            signal = m_ap_list[i].rssi();
            id = i;
        }
    }
    if(id!=-500)
    {
        return &m_ap_list[id];
    }
    else
    {
        return nullptr;
    }
}

void ap_list::push_back(wpa_access_point& ap)
{
    lock_guard<mutex> lck(m_locker);
    bool m_bfinded = false;
    for(auto &i : m_ap_list)
    {
        if(i.bssid() == ap.bssid())
        {
            m_bfinded  = true;
            break;
        }
    }
    if(!m_bfinded)
    {
        m_ap_list.push_back(ap);
    }
}
void ap_list::remove_all_exclude(const string& ssid)
{
    lock_guard<mutex> lck(m_locker);
    for(size_t i=0;i<m_ap_list.size();i++)
    {
        if(m_ap_list[i].ssid() != ssid)
        {
            m_ap_list.erase(m_ap_list.begin()+i);
        }
    }

}
void ap_list::remove(const string& ssid)
{
    lock_guard<mutex> lck(m_locker);
    for(size_t i=0;i<m_ap_list.size();i++)
    {
        if(m_ap_list[i].ssid() == ssid)
        {
            m_ap_list.erase(m_ap_list.begin() + i);
        }
    }
}
void ap_list::remove(mac_addr& addr)
{
    lock_guard<mutex> lck(m_locker);
   for(size_t i=0;i<m_ap_list.size();i++)
   {
        if(m_ap_list[i].bssid()==addr)
        {
            m_ap_list.erase(m_ap_list.begin() + i);
        }
   }
}
wpa_access_point& ap_list::operator [] (size_t pos)
{
    lock_guard<mutex> lck(m_locker);
    if(pos < m_ap_list.size())
    {
        return m_ap_list[pos];
    }
    else
    {
        throw runtime_error("ap_list :: operator[] : out of range");
    }
}



