/*
 * (c) 1997-2013 Netflix, Inc.  All content herein is protected by
 * U.S. copyright and other applicable intellectual property laws and
 * may not be copied without the express permission of Netflix, Inc.,
 * which reserves all rights. Reuse of any of this content for any
 * purpose without the permission of Netflix, Inc. is strictly
 * prohibited.
 */

#ifndef DataBuffer_h
#define DataBuffer_h

#include <string.h>
#include <tr1/memory>
// #include <nrdbase/Noncopyable.h>
#include <vector>
#include <list>
#include <string>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <zlib.h>
#include <iostream>

using std::tr1::shared_ptr;
using std::tr1::enable_shared_from_this;

namespace netflix {
namespace base {

class Mutex
{
public:
    void lock() {}
    void unlock() {}
};

class ScopedMutex
{
public:
    ScopedMutex(Mutex &) {}
};

class DataPool;
class DataChunk
{
public:
    ~DataChunk();
private:
    DataChunk();

    unsigned char *data;
    int size, capacity;
    enum State {
        FromRawData,
        Pool,
        Allocated
    } state;
    shared_ptr<DataPool> pool;

    void resize(int size);
    friend class DataPool;
    friend class DataBuffer;
};

template <typename T>
class DataPointer
{
public:

    operator T() { return mData; }
    operator const T() const { return mData; }

    T data()  { return mData; }
    const T data() const { return mData; }
private:
    DataPointer(const shared_ptr<DataPool> &pool, T t)
        : mData(t)
    {
        if (pool)
            mPool.reset(new Data(pool));
    }
    DataPointer() : mData(0) {}

    struct Data {
        Data(const shared_ptr<DataPool> &p)
            : pool(p)
        {}
        ~Data();

        shared_ptr<DataPool> pool;
    };
    T mData;
    shared_ptr<Data> mPool;

    friend class DataBuffer;
};

class DataBuffer
{
public:
    typedef const unsigned char & const_reference;
    typedef unsigned char & reference;
    typedef unsigned char value_type;

    inline DataBuffer(int cap = 0);
    inline DataBuffer(const unsigned char *d, int len = -1);
    inline DataBuffer(const char *d, int len = -1);
    inline DataBuffer(const std::string &str);
    inline DataBuffer(const std::vector<unsigned char> &v);

    inline static DataBuffer fromRawData(const unsigned char *data, int size);
    inline static DataBuffer fromRawData(const char *data, int size);
    inline static DataBuffer fromFile(const char *path, int start = 0, int size = -1, bool *ok = 0);

    inline void clear();
    inline void reserve(int cap);

    template <typename T> inline void append(const T *d, int len);
    template <typename T> inline void append(T t);
    inline void append(const std::string &data);
    inline void append(const char *nullTerminated);
    inline void append(const DataBuffer &buffer);

    template <typename T> inline void push_back(T *d, int len) { append<T>(d, len); }
    template <typename T> inline void push_back(T t) { append<T>(t); }
    inline void push_back(const std::string &data) { append(data); }
    inline void push_back(const char *nullTerminated) { append(nullTerminated); }
    inline void push_back(const DataBuffer &buffer) { append(buffer); }

    inline void remove(int index, int len);
    inline int indexOf(const DataBuffer &needle, int offset=0) const;
    inline int replace(const DataBuffer &needle, const DataBuffer &value);
    inline void replace(int index, int len, const DataBuffer &value);
    inline bool contains(const DataBuffer &needle) const { return indexOf(needle) != -1; }

    inline void setUsed(int bytes);

    inline std::string toString() const; // deep copy
    inline std::vector<unsigned char> toVector() const; // deep copy

    inline int size() const;
    inline int length() const { return size(); }
    inline bool isEmpty() const;
    inline bool empty() const;
    inline int capacity() const;

    inline DataPointer<const char*> c_str() const;
    inline DataPointer<unsigned char*> data();
    inline DataPointer<const unsigned char*> data() const;
    template <typename T> inline DataPointer<T> data();
    template <typename T> inline DataPointer<const T> data() const;

    inline bool ownsData() const;

    enum CaseSensitivity {
        CaseSensitive,
        CaseInsensitive
    };
    inline int compare(const DataBuffer &other, int max = -1, CaseSensitivity cs = CaseSensitive) const;
    inline int compare(const std::string &other, int max = -1, CaseSensitivity cs = CaseSensitive) const;
    inline int compare(const char *other, int max = -1, CaseSensitivity cs = CaseSensitive) const;

    template <typename T> inline DataBuffer &operator+=(T t) { append(t); return *this; }

    enum Encoding {
        Encoding_Base64,
        Encoding_Url,
        Encoding_Hex,
        Encoding_Percent = Encoding_Url,
    };
    bool isBinary(int max = -1) const;
    DataBuffer encode(Encoding encoding) const;
    DataBuffer decode(Encoding encoding) const;
    inline DataBuffer toBase64() const { return encode(Encoding_Base64); }
    std::string toBase64String() const;
    inline DataBuffer toUrlEncoded() { return encode(Encoding_Percent); }
    inline DataBuffer toHex() const { return encode(Encoding_Hex); }
    static inline DataBuffer fromBase64(const DataBuffer &encoded) { return encoded.decode(Encoding_Base64); }
    static inline DataBuffer fromUrl(const DataBuffer &encoded) { return encoded.decode(Encoding_Url); }
    static inline DataBuffer fromHex(const DataBuffer &encoded) { return encoded.decode(Encoding_Hex); }

    enum Hash {
        Hash_SHA1,
        Hash_SHA256,
        Hash_MD5
    };
    DataBuffer hash(Hash hash, bool *ok = 0) const;
    enum CompressionMode {
        Compression_Normal,
        Compression_GZip,
        Compression_Base64
    };
    DataBuffer compress(CompressionMode mode, bool *ok = 0) const;
    DataBuffer uncompress(CompressionMode mode, bool *ok = 0) const;
private:
    DataBuffer(const shared_ptr<DataChunk> &chunk)
        : mData(chunk)
    {}
    typedef DataChunk Data;
    shared_ptr<Data> mData;

    static void countStats(int count);
    friend class DataPool;
};

class DataPool : public enable_shared_from_this<DataPool> // Noncopyable
{
public:
    DataPool();
    ~DataPool();

    void init(int size);
    void lock()
    {
        mMutex.lock();
    }

    void unlock()
    {
        mMutex.unlock();
    }

    void defrag() { ScopedMutex lock(mMutex); defrag_helper(); }
    DataBuffer create(int size);
    int size() const { ScopedMutex lock(mMutex); return mSize; }
    void dump();
private:
    int defrag_helper();
    typedef DataChunk Chunk;
    void resize(Chunk *chunk, int size);
    void split(std::list<shared_ptr<Chunk> >::iterator it, int size);

    unsigned char *mData;
    int mSize;
    std::list<shared_ptr<Chunk> > mChunks;
    friend class DataBuffer;
    friend class DataChunk;
    mutable Mutex mMutex;
};

template <typename T>
inline DataPointer<T>::Data::~Data()
{
    if (pool)
        pool->unlock();
}

inline DataChunk::DataChunk()
    : data(0), size(0), capacity(0), state(Allocated)
{

}

inline DataChunk::~DataChunk()
{
    if (state == Allocated && data) {
        assert(!pool);
        free(data);
    }

}

inline void DataChunk::resize(int size)
{
    if (pool) {
        pool->resize(this, size);
    } else {
        capacity = size;
        data = reinterpret_cast<unsigned char*>(realloc(data, capacity + 1));
    }
    // unsigned char *data;
    // int size, capacity;
    // enum State {
    //     Pool,
    //     Alloced,
    //     FromRawData
    // } state;

}

inline DataBuffer::DataBuffer(int cap)
{
    reserve(cap);
}

inline DataBuffer::DataBuffer(const unsigned char *d, int len)
{
    if (!d)
        return;
    if (len == -1)
        len = strlen(reinterpret_cast<const char*>(d));
    if (len)
        append(d, len);
}

inline DataBuffer::DataBuffer(const char *d, int len)
{
    if (!d)
        return;
    if (len == -1)
        len = strlen(d);
    append(d, len);
}

inline DataBuffer::DataBuffer(const std::string &str)
{
    append(str.c_str(), str.size());
}

inline DataBuffer::DataBuffer(const std::vector<unsigned char> &v)
{
    append(&v[0], v.size());
}

inline DataBuffer DataBuffer::fromRawData(const unsigned char *data, int size)
{
    DataBuffer ret;
    if (!data || !size)
        return ret;
    ret.mData.reset(new Data);
    ret.mData->state = Data::FromRawData;
    ret.mData->data = const_cast<unsigned char*>(data); // awful
    ret.mData->size = size;
    return ret;
}

inline DataBuffer DataBuffer::fromRawData(const char *data, int size)
{
    DataBuffer ret;
    if (!data || !size)
        return ret;
    ret.mData.reset(new Data);
    ret.mData->state = Data::FromRawData;
    ret.mData->data = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(data)); // awful
    ret.mData->size = size;
    return ret;
}

inline DataBuffer DataBuffer::fromFile(const char *path, int start, int size, bool *ok)
{
    assert(start >= 0);
    DataBuffer ret;
    FILE *f = fopen(path, "r");
    if (!f) {
        if (ok)
            *ok = false;
        return ret;
    }
    if (ok)
        *ok = true;
    fseek(f, 0, SEEK_END);
    const int fileSize = ftell(f);
    if (size == -1) {
        size = fileSize - start;
    } else {
        size = std::min(fileSize - start, size);
    }
    if (size > 0) {
        fseek(f, start, SEEK_SET);
        ret.reserve(size);
        while (ret.mData->size < size) {
            const int read = fread(ret.mData->data + ret.mData->size, sizeof(unsigned char), size - ret.mData->size, f);
            if (read <= 0)
                break;
            ret.mData->size += read;
        }
        if (ret.mData->size != size)
            ret.clear();
    }
    fclose(f);

    return ret;
}

inline void DataBuffer::clear()
{
    mData.reset();
}

inline void DataBuffer::reserve(int cap)
{
    assert(!mData || mData->state != Data::FromRawData);
    assert(!mData || mData.use_count() == 1);
    assert(cap >= 0);
    if (cap) {
        if (!mData) {
            mData.reset(new Data);
            mData->resize(cap);
            // mData->data = reinterpret_cast<unsigned char*>(realloc(mData->data, cap + 1));
            // DataBuffer::countStats(cap + 1);
            // mData->capacity = cap;
        } else if (cap != mData->capacity && (cap > mData->capacity || (cap && cap >= mData->size))) {
            mData->resize(cap);
            // mData->data = reinterpret_cast<unsigned char*>(realloc(mData->data, cap + 1));
            // DataBuffer::countStats(cap - mData->capacity + 1);
            // mData->capacity = cap;
        }
    } else if (mData && !mData->size) {
        clear();
    }
}

template <typename T> inline void DataBuffer::append(const T *t, int len)
{
    if (len) {
        (void)static_cast<long long>(T());
        len *= sizeof(T);
        assert(t);
        if (!mData) {
            reserve(len);
        } else {
            assert(mData->state != Data::FromRawData);
            assert(mData.use_count() == 1);
            const int available = mData->capacity - mData->size;
            if (available < len) {
                const int needed = len - available;
                const int additional = std::min(needed / 2, 1024);
                reserve(mData->capacity + needed + additional);
            }
        }
        assert(mData);
        memcpy(mData->data + mData->size, t, len);
        mData->size += len;
        mData->data[mData->size] = '\0';
    }
}

template <typename T> inline void DataBuffer::append(T t)
{
    (void)static_cast<long long>(T());
    append(&t, 1);
}

inline void DataBuffer::append(const DataBuffer &buffer)
{
    DataPointer<const unsigned char*> ptr = buffer.data();
    append(ptr.data(), buffer.size());
}

inline void DataBuffer::append(const char *nullTerminated)
{
    append(nullTerminated, strlen(nullTerminated));
}

inline void DataBuffer::append(const std::string &data)
{
    append(data.c_str(), data.size());
}

inline void DataBuffer::replace(int index, int len, const DataBuffer &value)
{
    assert(mData.use_count() == 1);
    assert(mData->state != Data::FromRawData);
    if (!len || index + len > mData->size)
        return;

    if (!value.size()) {
        remove(index, len);
    } else if (len == mData->size) {
        operator=(value);
    } else if (len == value.size()) {
        memcpy(data() + index, value.data(), len);
    } else if (len > value.size()) { // this won't release preallocation
        unsigned char *bytes = data();
        memcpy(bytes + index, value.data(), value.size());
        memmove(bytes + index + value.size(), bytes + index + len, mData->size - index - len + 1);
        mData->size -= (len - value.size());
    } else {
        const int diff = (value.size() - len);
        reserve(mData->size + diff);
        unsigned char *bytes = data();
        memmove(bytes + index + value.size(), bytes + index + len, mData->size - index - len + 1);
        memcpy(bytes + index, value.data(), value.size());
        mData->size += diff;
    }
}

inline int DataBuffer::replace(const DataBuffer &needle, const DataBuffer &value)
{
    int count = 0;
    int index = 0;
    while (true) {
        index = indexOf(needle, index);
        if (index == -1)
            break;
        replace(index, needle.size(), value);
        index += value.size();
        ++count;
    }
    return count;
}

inline void DataBuffer::remove(int index, int len)
{
    assert(mData.use_count() == 1);
    len = std::min(mData->size - index, len);
    if (len) {
        if (index + len == mData->size) {
            if (!index) {
                clear();
            } else {
                mData->size -= len;
                mData->data[mData->size] = '\0';
            }
        } else {
            unsigned char *bytes = data();
            memmove(bytes + index, bytes + len + index, mData->size - len - index + 1); // include \0
            mData->size -= len;
        }
    }
}

inline int DataBuffer::indexOf(const DataBuffer &needle, int index) const
{
    const int mySize = size();
    const int hisSize = needle.size();
    if (mySize-index < hisSize || !hisSize)
        return -1;

    const char *me = data<const char*>();
    const char *him = needle.data<const char*>();

    int matched = 0;
    for (int i=index; i<mySize; ++i) {
        if (me[i] == him[matched]) {
            if (++matched == hisSize)
                return i - matched + 1;
        } else if (mySize - i > hisSize) {
            matched = 0;
        } else {
            break;
        }
    }
    return -1;
}

inline std::string DataBuffer::toString() const // inefficient
{
    return mData ? std::string(data<const char*>(), size()) : std::string();
}

inline std::vector<unsigned char> DataBuffer::toVector() const // inefficient
{
    if (mData) {
        const unsigned char *d = mData->data;
        return std::vector<unsigned char>(d, d + mData->size);
    }
    return std::vector<unsigned char>();
}

inline int DataBuffer::size() const
{
    return mData ? mData->size : 0;
}

inline bool DataBuffer::isEmpty() const
{
    return !size();
}

inline bool DataBuffer::empty() const
{
    return isEmpty();
}

inline DataPointer<const char *> DataBuffer::c_str() const
{
    if (!mData)
        return DataPointer<const char *>();
    if (mData->pool)
        mData->pool->lock();
    return DataPointer<const char *>(mData->pool, reinterpret_cast<const char *>(mData->data));
}

inline DataPointer<unsigned char *> DataBuffer::data()
{
    if (!mData)
        return DataPointer<unsigned char *>();
    if (mData->pool)
        mData->pool->lock();
    return DataPointer<unsigned char *>(mData->pool, mData->data);
}

inline DataPointer<const unsigned char *> DataBuffer::data() const
{
    if (!mData)
        return DataPointer<const unsigned char *>();
    if (mData->pool)
        mData->pool->lock();
    return DataPointer<const unsigned char *>(mData->pool, mData->data);
}

template <typename T> inline DataPointer<T> DataBuffer::data()
{
    if (!mData)
        return DataPointer<T>();
    if (mData->pool)
        mData->pool->lock();
    return DataPointer<T>(mData->pool, reinterpret_cast<T>(mData->data));
}

template <typename T> inline DataPointer<const T> DataBuffer::data() const
{
    if (!mData)
        return DataPointer<const T>();
    if (mData->pool)
        mData->pool->lock();
    return DataPointer<const T>(mData->pool, reinterpret_cast<const T>(mData->data));
}

inline int DataBuffer::capacity() const
{
    return mData ? mData->capacity : 0;
}

inline void DataBuffer::setUsed(int size)
{
    assert(mData);
    assert(mData->state != Data::FromRawData);
    assert(size <= mData->capacity);
    mData->size = size;
    if (size > 0)
        mData->data[size] = '\0';
}

inline bool DataBuffer::ownsData() const
{
    return mData && mData->state != Data::FromRawData;
}

inline bool DataBuffer::isBinary(int max) const
{
    const int length = max == -1 ? size() : max;
    for (int i = 0; i < length; ++i) {
        if (!isprint(mData->data[i]))
           return true;
    }
    return false;
}

inline int DataBuffer::compare(const DataBuffer &other, int max, CaseSensitivity cs) const
{
    return compare(other.data<const char*>(), max, cs);
}

inline int DataBuffer::compare(const std::string &other, int max, CaseSensitivity cs) const
{
    return compare(other.c_str(), max, cs);
}

inline int DataBuffer::compare(const char *other, int max, CaseSensitivity cs) const
{
    if (mData && mData->data == reinterpret_cast<const unsigned char*>(other))
        return 0;
    if (!mData)
        return !other ? 0 : -1;
    if (!other)
        return 1;

    const char *str = reinterpret_cast<const char *>(mData->data);
    if (max == -1) {
        if (cs == CaseSensitive) {
            return strcmp(str, other);
        } else {
            return strcasecmp(str, other);
        }
    }

    if (cs == CaseSensitive) {
        return strncmp(str, other, max);
    } else {
        return strncasecmp(str, other, max);
    }
}

inline bool operator==(const DataBuffer &l, const DataBuffer &r) { return !l.compare(r); }
inline bool operator==(const DataBuffer &l, const std::string &r) { return !l.compare(r); }
inline bool operator==(const std::string &l, const DataBuffer &r) { return !r.compare(l); }
inline bool operator==(const DataBuffer &l, const char *r) { return !l.compare(r); }
inline bool operator==(const char *l, const DataBuffer &r) { return !r.compare(l); }

inline bool operator!=(const DataBuffer &l, const DataBuffer &r) { return l.compare(r) != 0; }
inline bool operator!=(const DataBuffer &l, const std::string &r) { return l.compare(r) != 0; }
inline bool operator!=(const std::string &l, const DataBuffer &r) { return r.compare(l) != 0; }
inline bool operator!=(const DataBuffer &l, const char *r) { return l.compare(r) != 0; }
inline bool operator!=(const char *l, const DataBuffer &r) { return r.compare(l) != 0; }

inline bool operator<(const DataBuffer &l, const DataBuffer &r) { return l.compare(r) < 0; }
inline bool operator<(const DataBuffer &l, const std::string &r) { return l.compare(r) < 0; }
inline bool operator<(const std::string &l, const DataBuffer &r) { return r.compare(l) > 0; }
inline bool operator<(const DataBuffer &l, const char *r) { return l.compare(r) < 0; }
inline bool operator<(const char *l, const DataBuffer &r) { return r.compare(l) > 0; }

inline bool operator>(const DataBuffer &l, const DataBuffer &r) { return l.compare(r) > 0; }
inline bool operator>(const DataBuffer &l, const std::string &r) { return l.compare(r) > 0; }
inline bool operator>(const std::string &l, const DataBuffer &r) { return r.compare(l) < 0; }
inline bool operator>(const DataBuffer &l, const char *r) { return l.compare(r) > 0; }
inline bool operator>(const char *l, const DataBuffer &r) { return r.compare(l) < 0; }

} // namespace base
} // namespace netflix


#endif
