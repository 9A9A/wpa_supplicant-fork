#include "wpa_roam.h"

wpa_event_monitor::wpa_event_monitor(shared_ptr<wpa_ctrl_iface>& iface)
{
    m_pwpa_ctrl_iface = iface;
    if(!m_pwpa_ctrl_iface->is_attached())
    {
        throw runtime_error("wpa_ctrl_iface isn't attached to wpa_supplicant");
    }
    m_pwpa_ctrl_iface->OnMessageReceived = bind(&wpa_event_monitor::parser,this,placeholders::_1);
}
wpa_event_monitor::~wpa_event_monitor()
{
    if(m_pwpa_ctrl_iface)
    {
        m_pwpa_ctrl_iface->OnMessageReceived = nullptr;
    }
    OnEventTerminating = nullptr;
    OnEventConnected = nullptr;
    OnEventDisconnected = nullptr;
    OnEventAssociating = nullptr;
    OnEventScanStarted = nullptr;
    OnEventScanResultsAvailable = nullptr;
    OnEventBSSAdded = nullptr;
    OnEventBSSRemoved = nullptr;
#ifdef DEBUG
    cout << CurrentTime() << __CLASS__ << " destroyed\n";
#endif
}
shared_ptr<wpa_ctrl_iface>& wpa_event_monitor::iface()
{
    return m_pwpa_ctrl_iface;
}
void wpa_event_monitor::parser(wpa_response& response)
{
    auto response_str = response.to_string();
    if(response_str.find(WPA_EVENT_CONNECTED)!=string::npos)
    {
        auto string_to_parse = response_str;
        mac_addr addr_t(string_to_parse.substr(string_to_parse.find("Connection to ")+sizeof("Connection to "),MAX_MAC_ADDR_SIZE));
        if(OnEventConnected)
        {
            OnEventConnected(addr_t);
        }
    }
    else if(response_str.find(WPA_EVENT_DISCONNECTED)!=string::npos)
    {
        auto string_to_parse = response_str;
        mac_addr addr_t(string_to_parse.substr(string_to_parse.find("bssid=")+sizeof("bssid=")-1,MAX_MAC_ADDR_SIZE));
        if(OnEventDisconnected)
        {
            OnEventDisconnected(addr_t);
        }
    }
    else if(response_str.find(WPA_EVENT_SCAN_STARTED)!=string::npos)
    {
        if(OnEventScanStarted)
        {
            OnEventScanStarted();
        }
    }
    else if(response_str.find(WPA_EVENT_SCAN_RESULTS)!=string::npos)
    {
        if(OnEventScanResultsAvailable)
        {
            OnEventScanResultsAvailable();
        }
    }
    else if(response_str.find(WPA_EVENT_TERMINATING)!=string::npos)
    {
        if(OnEventTerminating)
        {
            OnEventTerminating();
        }
    }
    else if(response_str.find(WPA_EVENT_BSS_ADDED)!=string::npos)
    {
        auto string_to_parse = response_str;
        mac_addr addr_t(string_to_parse.substr(string_to_parse.size()-MAX_MAC_ADDR_SIZE,MAX_MAC_ADDR_SIZE));
        if(OnEventBSSAdded)
        {
            OnEventBSSAdded(addr_t);
        }
    }
    else if(response_str.find(WPA_EVENT_BSS_REMOVED)!=string::npos)
    {
        auto string_to_parse = response_str;
        mac_addr addr_t(string_to_parse.substr(string_to_parse.size()-MAX_MAC_ADDR_SIZE,MAX_MAC_ADDR_SIZE));
        if(OnEventBSSRemoved)
        {
            OnEventBSSRemoved(addr_t);
        }
    }
    else if(response_str.find(WPA_EVENT_ASSOCIATED)!=string::npos)
    {
        auto string_to_parse = response_str;
#ifdef DEBUG
        cout << string_to_parse << endl;
#endif
        mac_addr addr_t(string_to_parse.substr(string_to_parse.find(WPA_EVENT_ASSOCIATED)+sizeof(WPA_EVENT_ASSOCIATED)-1,MAX_MAC_ADDR_SIZE));
        if(OnEventAssociating)
        {
            OnEventAssociating(addr_t);
        }
    }
#ifdef DEBUG
    else
    {
        cout << CurrentTime() << "Stub Worked: " <<  response_str << endl;
    }
#endif
}

wpa_roamer::wpa_roamer(shared_ptr<wpa_event_monitor>& monitor,size_t Hysteresis,size_t TransitionTime,int ScanThreshold,int MinRssi )
{
    if(monitor)
    {
        m_bThreadActive = false;
        m_nScanThresholdLevel = ScanThreshold;
        m_nHysteresis = Hysteresis;
        m_nTransitionTime = std::chrono::seconds(TransitionTime);


        m_nMinRssiLevel = MinRssi;
        m_bInActiveMode = false;
        m_pevent_mon = monitor;
        m_bConnected = false;
        m_bShutdownMode = false;
        m_current_bssid = mac_addr();
#ifdef DEBUG
        cout << "Initialized :\nScan Threshold : " << m_nScanThresholdLevel << "\nMin Rssi : " << m_nMinRssiLevel << "\nHysteresis : " << m_nHysteresis << "\nTransition time : " << m_nTransitionTime.count() << endl;
#endif
        m_pevent_mon->OnEventTerminating = bind(&wpa_roamer::OnTerminating,this);
        m_pevent_mon->OnEventConnected = bind(&wpa_roamer::OnConnected,this,placeholders::_1);
        m_pevent_mon->OnEventDisconnected = bind(&wpa_roamer::OnDisconnected,this,placeholders::_1);
        m_pevent_mon->OnEventAssociating = bind(&wpa_roamer::OnAssociating,this,placeholders::_1);
        m_pevent_mon->OnEventScanStarted = bind(&wpa_roamer::OnScanStarted,this);
        m_pevent_mon->OnEventScanResultsAvailable = bind(&wpa_roamer::OnScanResults,this);
        m_pevent_mon->OnEventBSSAdded = bind(&wpa_roamer::OnBSSAdded,this,placeholders::_1);
        m_pevent_mon->OnEventBSSRemoved = bind(&wpa_roamer::OnBSSRemoved,this,placeholders::_1);


        start_thread();
        update_connection_state();
        passive_scanning();
    }
    else
    {
        throw runtime_error("wpa_roamer : wpa_event_monitor ptr is nullptr");
    }
}
wpa_roamer::~wpa_roamer()
{
    stop_thread();
    unbind_callbacks();
#ifdef DEBUG
    cout << CurrentTime() << __CLASS__ << " destroyed\n";
#endif
}

shared_ptr<wpa_ctrl_iface>& wpa_roamer::iface()
{
    return m_pevent_mon->iface();
}
void wpa_roamer::unbind_callbacks()
{
    m_pevent_mon->OnEventTerminating = nullptr;
    m_pevent_mon->OnEventConnected = nullptr;
    m_pevent_mon->OnEventDisconnected = nullptr;
    m_pevent_mon->OnEventAssociating = nullptr;
    m_pevent_mon->OnEventScanStarted = nullptr;
    m_pevent_mon->OnEventScanResultsAvailable = nullptr;
    m_pevent_mon->OnEventBSSAdded = nullptr;
    m_pevent_mon->OnEventBSSRemoved = nullptr;
}
void wpa_roamer::OnAssociating(mac_addr& addr)
{
    lock_guard<mutex> lock(m_locker);
#ifdef DEBUG
    cout << CurrentTime() << __CLASS__ << "::" << __func__  << " : "<< addr.to_string() << endl;
#endif
    m_bConnected = true;
    m_current_bssid = addr;
    update_connection_state();
    unlock_polling_thread();
}
void wpa_roamer::OnBSSAdded(mac_addr& addr)
{
    lock_guard<mutex> lock(m_locker);
#ifdef DEBUG
    cout << CurrentTime() << __CLASS__ << "::" << __func__  << " : " << addr.to_string() << endl;
#endif
    wpa_access_point access_point_t;
    access_point_t.set_bssid(addr);
    m_scanned_ap_list.push_back(access_point_t);
}
void wpa_roamer::OnBSSRemoved(mac_addr& addr)
{
    lock_guard<mutex> lock(m_locker);
#ifdef DEBUG
    cout << CurrentTime() << __CLASS__ << "::" << __func__  << " : " << addr.to_string() << endl;
#endif
    m_scanned_ap_list.remove(addr);
}
void wpa_roamer::OnDisconnected(mac_addr& addr)
{
    lock_guard<mutex> lock(m_locker);
#ifdef DEBUG
    cout << CurrentTime() << __CLASS__ << "::" << __func__  << " : " << addr.to_string() << endl;
#endif
    if(m_bConnected)
    {
        m_bConnected = false;
        m_bInActiveMode = false;
        m_current_bssid = mac_addr();
    }
}
void wpa_roamer::OnConnected(mac_addr& addr)
{
    lock_guard<mutex> lock(m_locker);
#ifdef DEBUG
    cout << CurrentTime() << addr.to_string() << endl;
#endif
    m_bConnected = true;
    m_current_bssid = addr;
    update_connection_state();
}
void wpa_roamer::OnScanStarted()
{
    lock_guard<mutex> lock(m_locker);
#ifdef DEBUG
    cout << CurrentTime() << __CLASS__ << "::" << __func__ << endl;
#endif

}
void wpa_roamer::OnScanResults()
{
    lock_guard<mutex> lock(m_locker);
    unique_lock<mutex> lck(m_synchronized);
#ifdef DEBUG
    cout << CurrentTime() << __CLASS__ << "::" << __func__  << endl;
#endif
    auto response_t = m_pevent_mon->iface()->request(SCAN_RESULTS);
    parse_scan_request(response_t);
    auto connected_list = m_scanned_ap_list.get_all_by_ssid(m_ssid);
    update_connection_state();

    if(m_bConnected)
    {
#ifdef DEBUG
        cout << "Connected to : " << *m_scanned_ap_list.find_ap_by_bssid(m_current_bssid);
#endif
        auto ptr = m_scanned_ap_list.find_ap_by_bssid(m_current_bssid);
        if(ptr)
        {
            m_current_rssi = ptr->rssi();
            m_bInActiveMode = (m_current_rssi < m_nScanThresholdLevel) ? true : false;
#ifdef DEBUG
            if(m_bInActiveMode)
            {
                cout << "\t"<< m_current_rssi << " < " << m_nScanThresholdLevel << " Active\n";
            }
            else
            {
                cout << "\t"<< m_current_rssi << " > " << m_nScanThresholdLevel << " Passive\n";
            }
#endif
            if(m_bInActiveMode)
            {
                if(connected_list.size() >= 2)
                {
                    if(m_current_rssi >= m_nMinRssiLevel)
                    {
                        soft_roam(&connected_list);
                    }
                    else
                    {
                        hard_roam(&connected_list);
                    }
                }
            }
            else
            {
                cancel_hysteresis(&m_scanned_ap_list);
            }
        }
#ifdef DEBUG
        else
        {
            cout << "PTR IS NULL\n";
        }
#endif
    }
    else
    {
#ifdef DEBUG
        cout << "Disconnected\n";
#endif
        auto ptr = m_scanned_ap_list.get_best_signal(m_ssid);
        if(ptr && !m_bShutdownMode)
        {
            make_roam(m_ssid,ptr->bssid());
        }
    }
    show_list(&connected_list);
    unlock_polling_thread();
}
void wpa_roamer::show_list(ap_list* ptr)
{
#ifdef DEBUG
    if(ptr)
    {
        for(auto &i : *ptr)
        {
            cout << i;
        }
    }
#endif
}
void wpa_roamer::cancel_hysteresis(ap_list* ptr)
{
    if(ptr)
    {
        for(auto &i : *ptr)
        {
            auto ap_ptr = m_scanned_ap_list.find_ap_by_bssid(i.bssid());
            if(ap_ptr)
            {
                ap_ptr->cancel_hysteresis();
            }
        }
    }
}

void wpa_roamer::make_roam(const string& _ssid,const mac_addr& _bssid)
{
    cout << CurrentTime() << "ROAMING FROM " << m_current_bssid.to_string() << " TO " << _bssid.to_string() << endl;
    m_pevent_mon->iface()->request(string(BSSID) + " " + to_string(get_network_id(_ssid)) + " " + _bssid.to_string());
    m_pevent_mon->iface()->request(string(ROAM) + " " + _bssid.to_string());
    m_bInActiveMode = false;
}
void wpa_roamer::hard_roam(ap_list* ptr)
{
    if(ptr)
    {
        cancel_hysteresis(&m_scanned_ap_list);
        auto bst_ptr = ptr->get_best_signal(m_current_bssid);
        if(bst_ptr && (bst_ptr->rssi() > m_current_rssi))
        {
#ifdef DEBUG
            cout << "HARD ";
#endif
            make_roam(m_ssid,bst_ptr->bssid());
        }
    }
}
void wpa_roamer::soft_roam(ap_list* ptr)
{
    if(ptr)
    {
        ptr->sort();
        bool m_bRoamed = false;
        for(auto &i: *ptr)
        {
            if(i.bssid() != m_current_bssid && !m_bRoamed)
            {
                if(i.is_hysteresis())
                {
                    if(i.check_hysteresis(m_current_rssi,m_nHysteresis,m_nMinRssiLevel,m_nTransitionTime))
                    {
#ifdef DEBUG
                        cout << "SOFT ";
#endif
                        if(!m_bRoamed)
                        {
                            make_roam(m_ssid,i.bssid());
                            m_bRoamed = true;
                        }
                        cancel_hysteresis(&m_scanned_ap_list);
                    }
                }
                else
                {
                    i.start_hysteresis(m_current_rssi,m_nHysteresis);
                }
                auto ap_ptr = m_scanned_ap_list.find_ap_by_bssid(i.bssid());
                if(ap_ptr)
                {
                    *ap_ptr = i;
                }
            }
        }
    }
}
void wpa_roamer::unlock_polling_thread()
{
    m_bNotified = true;
    m_changed.notify_one();
}
void wpa_roamer::OnTerminating()
{
    lock_guard<mutex> lock(m_locker);
#ifdef DEBUG
    cout << CurrentTime() << __CLASS__ << "::" << __func__  << endl;
#endif
    unlock_polling_thread();
    m_bShutdownMode = true;

    stop_thread();
    unbind_callbacks();
    cout << "wpa_supplicant closed\n";
    exit(0);
}
void wpa_roamer::update_connection_state()
{
//#ifdef DEBUG
//    cout << CurrentTime() << __CLASS__ << "::" << __func__  << endl;
//#endif
    auto response_t = m_pevent_mon->iface()->request(STATUS);
    auto response = response_t.to_string();
    if(response.find(CONNECTED_STATE)!=string::npos)
    {
        m_bConnected = true;
        size_t ssid_pos = response.find("\nssid=");
        size_t end_line_pos = response.find("\nid=");
        m_ssid = response.substr(ssid_pos + sizeof("\nssid=")-1,end_line_pos-ssid_pos-sizeof("\nssid"));
        auto bssid_t = response.substr(response.find("bssid=")+sizeof("bssid=")-1,MAX_MAC_ADDR_SIZE);
        m_current_bssid = mac_addr(bssid_t);
    }
    else if(response.find(DISCONNECTED_STATE)!=string::npos)
    {
        m_bConnected = false;
        m_current_bssid = mac_addr();
    }
}
void wpa_roamer::start_thread()
{
    if(m_pevent_mon && !m_bThreadActive)
    {
        m_bNotified = false;
        m_bThreadActive = true;
        m_pthread = make_unique<thread>([this]{thread_routine();});
    }
}
void wpa_roamer::stop_thread()
{
    if(m_bThreadActive)
    {
        m_bThreadActive = false;
        unlock_polling_thread();
        if(m_pthread)
        {
            m_pthread->join();
        }
    }
}
int wpa_roamer::get_network_id(const string& ssid)
{
    auto response_t = m_pevent_mon->iface()->request(LIST_NETWORKS);
    auto response = response_t.to_string();
    size_t pos;
    auto previous_find = [&response](size_t pos, char symbol) -> size_t
    {
        if(pos < response.size())
        {
            for(size_t i=pos;i >= 0; i--)
            {
                if( response [i] == symbol )
                {
                    return i;
                }
            }
            return string::npos;
        }
        return string::npos;
    };
    if((pos = response.find(ssid)) != string::npos )
    {
        size_t latest_end_line = previous_find( pos , '\n');
        string result = response.substr ( latest_end_line , response.find ( '\t', latest_end_line ) - latest_end_line );
        return stoi ( result );
    }
    return -1;
}
void wpa_roamer::thread_routine()
{
#ifdef DEBUG
    ThrdInf thr("RoamerScanThread");
#endif
    while(m_bThreadActive)
    {
        while(!m_bNotified)
        {
            unique_lock<mutex> lck(m_synchronized);
            m_changed.wait(lck);
        }
        m_bNotified = false;
        if(m_bThreadActive)
        {
            if(m_bInActiveMode)
            {
                if(m_bConnected)
                {
                    THREAD_WAIT(ACTIVE_SCAN_DELAY);
                    active_scanning();
                }
            }
            else
            {
                THREAD_WAIT(PASSIVE_SCAN_DELAY);
                passive_scanning();
            }
        }
    }
}
void wpa_roamer::active_scanning()
{
    auto current_ssid_aps = m_scanned_ap_list.get_all_by_ssid(m_ssid);
    set<int> frequencies_set;
    for(auto &i : current_ssid_aps)
    {
        frequencies_set.insert(i.frequency());
    }
    for(auto &i : frequencies_set)
    {
        string request_t = string(SCAN) + FREQ;
        request_t += to_string(i);
        m_pevent_mon->iface()->request(request_t);
        THREAD_WAIT(ACTIVE_SCAN_DELAY);
    }
}
void wpa_roamer::passive_scanning(size_t freq)
{
    if(!freq)
    {
        m_pevent_mon->iface()->request(PASSIVE_SCAN_REQUEST); // scan all channels
    }
    else
    {
        m_pevent_mon->iface()->request(SCAN_FREQUENCY + to_string(freq)); // scan only one specified channel
    }

//    for(int i=BASE_2_4GHZ_FREQ;i<=END_2_4GHZ_FREQ;i+=FREQ_OFFSET) // scan each channel with interval
//    {
////        string request_t = string(PASSIVE_SCAN_REQUEST) + FREQ + to_string(i);
//        string request_t = string(SCAN) + FREQ + to_string(i);
//        m_pevent_mon->iface()->request(request_t);
//        cout << "Scan freq : " << i << endl;
//        this_thread::sleep_for(milliseconds(PASSIVE_SCAN_CHANNEL_DELAY));
//    }
}
void wpa_roamer::parse_scan_request(wpa_response& resp)
{
    auto response_t = resp.to_string();
    response_t.erase(response_t.begin(),response_t.begin() + response_t.find("\n")+1);
    string line_to_parse;
    while(response_t.size())
    {
        line_to_parse = response_t.substr(0,response_t.find("\n"));
        auto bssid_t = line_to_parse.substr(0,line_to_parse.find("\t"));
        line_to_parse.erase(line_to_parse.begin(),line_to_parse.begin() + line_to_parse.find("\t") + 1);
        mac_addr addr_t(bssid_t);
        auto ptr = m_scanned_ap_list.find_ap_by_bssid(addr_t);
        if(ptr)
        {
            auto frequency_t = line_to_parse.substr(0,line_to_parse.find("\t"));
            ptr->set_frequency(stoi(frequency_t));
            line_to_parse.erase(line_to_parse.begin(),line_to_parse.begin() + line_to_parse.find("\t")+1);

            auto rssi_t = line_to_parse.substr(0,line_to_parse.find("\t"));
            ptr->set_rssi(stoi(rssi_t));
            line_to_parse.erase(line_to_parse.begin(),line_to_parse.begin() + line_to_parse.find("\t")+1);

            auto flags_t = line_to_parse.substr(0,line_to_parse.find("\t"));
            if((flags_t.find("WEP") != string::npos) || (flags_t.find("WPA")!=string::npos))
            {
                ptr->set_open(false);
            }
            else
            {
                ptr->set_open(true);
            }
            line_to_parse.erase(line_to_parse.begin(),line_to_parse.begin() + line_to_parse.find("\t")+1);

            auto ssid_t = line_to_parse.substr(0,line_to_parse.find("\n"));
            ptr->set_ssid(ssid_t);
            line_to_parse.erase(line_to_parse.begin(),line_to_parse.begin() + line_to_parse.find("\n")+1);
        }
        else
        {
            wpa_access_point access_point_t;
            access_point_t.set_bssid(addr_t);
            auto frequency_t = line_to_parse.substr(0,line_to_parse.find("\t"));
//                cout << frequency_t << " ";
            access_point_t.set_frequency(stoi(frequency_t));
            line_to_parse.erase(line_to_parse.begin(),line_to_parse.begin() + line_to_parse.find("\t")+1);

            auto rssi_t = line_to_parse.substr(0,line_to_parse.find("\t"));
//                cout << rssi_t << " ";
            access_point_t.set_rssi(stoi(rssi_t));
            line_to_parse.erase(line_to_parse.begin(),line_to_parse.begin() + line_to_parse.find("\t")+1);

            auto flags_t = line_to_parse.substr(0,line_to_parse.find("\t"));
            if((flags_t.find("WEP") != string::npos) || (flags_t.find("WPA")!=string::npos))
            {
                access_point_t.set_open(false);
            }
            else
            {
                access_point_t.set_open(true);
            }
            line_to_parse.erase(line_to_parse.begin(),line_to_parse.begin() + line_to_parse.find("\t")+1);

            auto ssid_t = line_to_parse.substr(0,line_to_parse.find("\n"));
//                cout << ssid_t;
            access_point_t.set_ssid(ssid_t);
            line_to_parse.erase(line_to_parse.begin(),line_to_parse.begin() + line_to_parse.find("\n")+1);
            m_scanned_ap_list.push_back(access_point_t);
        }
//            cout << endl;
        response_t.erase(response_t.begin(),response_t.begin()+response_t.find("\n")+1);
    }

}
#ifdef DEBUG
logger::logger(shared_ptr<wpa_roamer>& roamer,int log_period)
{
    m_pRoamer = roamer;
    m_period = log_period;
    m_pFileHandle = make_unique<fstream>(CurrentTime(true) + "_log.txt",ios::out);
    if(!m_pFileHandle->is_open())
    {
        *m_pFileHandle << CurrentTime() << endl;
        throw runtime_error("can't open the file");
    }
    m_pthread = make_unique<thread>([this]{thread_routine();});
    m_bActive = true;
}
logger::~logger()
{
    m_bActive = false;
    if(m_pthread)
    {
        m_pthread->join();
    }
    cout << CurrentTime() << __CLASS__ << " destroyed\n";
}

void logger::thread_routine()
{
    ThrdInf thr("LoggerThread");
    while(m_bActive)
    {
        *m_pFileHandle << CurrentTime(true) << "\t";
        if(m_pRoamer->m_bConnected)
        {
            *m_pFileHandle << "Connected:"<< m_pRoamer->m_current_bssid.to_string() << "\t||";
        }
        else
        {
            *m_pFileHandle << "Disconnected\t||";
        }
        for(auto &i : m_pRoamer->m_scanned_ap_list)
        {
            *m_pFileHandle << i.bssid().to_string() << "\t" << i.rssi() <<" ";
        }
        *m_pFileHandle << "\n";
        THREAD_WAIT(m_period);
    }
}
#endif
