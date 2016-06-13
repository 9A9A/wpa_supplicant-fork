#include "wpa_roam.h"
#ifdef DEBUG
ThreadInfo& ThreadInfo::instance()
{
    static ThreadInfo object;
    return object;
}
ThreadInfo::ThreadInfo()
{
}
ThreadInfo::~ThreadInfo()
{
    EraseThreadName();
}
void ThreadInfo::SetThreadName(const string& str)
{
    lock_guard<recursive_mutex> lck(m_locker);
    cout << CurrentTime() << str << " spawned\n";
    m_threadid[this_thread::get_id()] = str;
}
string ThreadInfo::ThreadId()
{
    lock_guard<recursive_mutex> lck(m_locker);
    return m_threadid[this_thread::get_id()];
}
void ThreadInfo::EraseThreadName()
{
    lock_guard<recursive_mutex> lck(m_locker);
    cout << CurrentTime() << ThreadId() << " killed\n";
    m_threadid.erase(this_thread::get_id());
}
#endif
string CurrentTime(bool flag)
{
    auto now = system_clock::now ( );
    time_t cur = system_clock::to_time_t ( now );
    tm* curtime;
    auto ms = duration_cast< seconds >( now.time_since_epoch ( ) );
//    localtime()
//    localtime_s( &curtime , &cur );
    curtime = localtime(&cur);
    string out;
    if(!flag)
    {
        out.append("\033[96m[");
    }
    if(curtime->tm_mday < 10)
    {
        out.append("0");
    }
    out.append(to_string(curtime->tm_mday));
    out.append(".");
    if(curtime->tm_mon+1 < 10)
    {
        out.append("0");
    }
    out.append(to_string(curtime->tm_mon+1));
    out.append(".");
    out.append(to_string(curtime->tm_year+1900));
    out.append(" ");
    if(curtime->tm_hour < 10)
    {
        out.append("0");
    }
    out.append(to_string(curtime->tm_hour));
    out.append(":");
    if(curtime->tm_min < 10)
    {
        out.append("0");
    }
    out.append(to_string(curtime->tm_min));
    out.append(":");
    if(curtime->tm_sec < 10)
    {
        out.append("0");
    }
    out.append(to_string(curtime->tm_sec));
    out.append(".");
    auto msc = duration_cast<milliseconds>(now.time_since_epoch()).count() - duration_cast<milliseconds>(ms).count();
    if(msc < 100)
    {
        out.append("0");
        if(msc < 10)
        {
            out.append("0");
        }
    }
    out.append(to_string(msc));
    if(!flag)
    {
        out.append("]\033[0m ");
    }
    return out;
}
wpa_response::wpa_response(size_t size) : m_nsize(size)
{
    if(m_nsize)
    {
        m_bempty = false;
        m_pmsg = new char [m_nsize];
    }
    else
    {
        m_bempty = true;
    }
}
wpa_response::wpa_response(const wpa_response& obj)
{
    if(this!=&obj)
    {
        m_pmsg = new char[obj.m_nsize];
        memcpy(m_pmsg,obj.m_pmsg,obj.m_nsize);
        m_nsize = obj.m_nsize;
    }
}
ostream& operator<<(ostream& os, wpa_response& obj)
{
    for(size_t i=0;i<obj.m_nsize;i++)
    {
        os << obj.m_pmsg[i];
    }
    return os;
}
ostream& operator<<(ostream& os, wpa_response obj)
{
    for(size_t i=0;i<obj.m_nsize;i++)
    {
        os << obj.m_pmsg[i];
    }
    return os;
}
string wpa_response::to_string() const
{
    string str_t;
    for(size_t i=0;i<m_nsize;i++)
    {
        str_t.push_back(m_pmsg[i]);
    }
    return str_t;
}
bool wpa_response::empty() const
{
    return m_bempty;
}
char* wpa_response::data()
{
    return m_pmsg;
}
size_t* wpa_response::size()
{
    return &m_nsize;
}
wpa_response::~wpa_response()
{
    delete[] m_pmsg;
}

mac_addr::mac_addr()
{
    m_addr[0] = 0;
    m_addr[1] = 0;
    m_addr[2] = 0;
    m_addr[3] = 0;
    m_addr[4] = 0;
    m_addr[5] = 0;
}
mac_addr::mac_addr(const string& addr)
{
    if(addr.size() <= MAX_MAC_ADDR_SIZE)
    {
        size_t counter_t=0;
        for(const auto &i : addr)
        {
            counter_t+=(i==':')?1:0;
        }
        if(counter_t == MAX_MAC_ADDR_DELIMS)
        {
            size_t index_t = 0;
            auto string_data_ptr = const_cast<char*>(addr.data());
            auto ptr_t = strtok(string_data_ptr,":");
            while(ptr_t)
            {
                size_t value_t = strtoul(ptr_t,nullptr,16);
                if(value_t > 255)
                {
                    throw runtime_error("mac_addr::mac_addr(const string& addr) : value overflow ( "+addr+" )");
                }
                m_addr[index_t++] = static_cast<byte>(value_t);
                ptr_t = strtok(nullptr,":");
            }
        }
        else
        {
            throw runtime_error("mac_addr::mac_addr(const string& addr) : invalid amount of delimeters ( " + addr + " )");
        }
    }
    else
    {
        throw runtime_error("mac_addr::mac_addr(const string& addr) : too long addr : " + addr + "(" + std::to_string(addr.size()) +"\17");
    }
}
mac_addr::mac_addr(byte b1,byte b2,byte b3,byte b4,byte b5, byte b6)
{
    m_addr[0] = b1;
    m_addr[1] = b2;
    m_addr[2] = b3;
    m_addr[3] = b4;
    m_addr[4] = b5;
    m_addr[5] = b6;
}
mac_addr::mac_addr(const mac_addr& obj)
{
    m_addr[0] = obj.m_addr[0];
    m_addr[1] = obj.m_addr[1];
    m_addr[2] = obj.m_addr[2];
    m_addr[3] = obj.m_addr[3];
    m_addr[4] = obj.m_addr[4];
    m_addr[5] = obj.m_addr[5];
}
mac_addr& mac_addr::operator = (const mac_addr& obj)
{
    if(this!=&obj)
    {
        m_addr[0] = obj.m_addr[0];
        m_addr[1] = obj.m_addr[1];
        m_addr[2] = obj.m_addr[2];
        m_addr[3] = obj.m_addr[3];
        m_addr[4] = obj.m_addr[4];
        m_addr[5] = obj.m_addr[5];
    }
    return *this;
}
bool mac_addr::empty() const
{
    return (m_addr[0] == 0 &&
            m_addr[1] == 0 &&
            m_addr[2] == 0 &&
            m_addr[3] == 0 &&
            m_addr[4] == 0 &&
            m_addr[5] == 0 ) ? true : false;
}
mac_addr& mac_addr::operator = (const string& str)
{
    mac_addr temp_object(str);
    *this = temp_object;
    return *this;
}
bool mac_addr::operator == (const mac_addr& obj) const
{
    return( m_addr[0] == obj.m_addr[0] &&
        m_addr[1] == obj.m_addr[1] &&
        m_addr[2] == obj.m_addr[2] &&
        m_addr[3] == obj.m_addr[3] &&
        m_addr[4] == obj.m_addr[4] &&
        m_addr[5] == obj.m_addr[5]);
}
bool mac_addr::operator != (const mac_addr& obj) const
{
    return (*this == obj) ? false : true;
}

byte* mac_addr::data()
{
    return m_addr;
}
string mac_addr::to_string() const
{
    stringstream sstream;
    for(size_t i=0;i<MAX_MAC_ADDR_LENGTH-1;i++)
    {
        if((int)m_addr[i]<16)
        {
            sstream << hex << "0" << (int)m_addr[i] << ":";
        }
        else
        {
            sstream << hex << (int)m_addr[i] << ":";
        }
    }
    if(m_addr[MAX_MAC_ADDR_LENGTH-1]<16)
    {
        sstream << hex << "0" << (int)m_addr[MAX_MAC_ADDR_LENGTH-1];
    }
    else
    {
        sstream << hex << (int)m_addr[MAX_MAC_ADDR_LENGTH-1];
    }
    return sstream.str();
}
ostream& operator<< (ostream& os, const mac_addr& mac)
{
    os << mac.to_string();
    return os;
}


