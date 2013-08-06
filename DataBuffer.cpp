/*
 * (c) 1997-2013 Netflix, Inc.  All content herein is protected by
 * U.S. copyright and other applicable intellectual property laws and
 * may not be copied without the express permission of Netflix, Inc.,
 * which reserves all rights. Reuse of any of this content for any
 * purpose without the permission of Netflix, Inc. is strictly
 * prohibited.
 */

#include "DataBuffer.h"
// #include "StringCompressor.h"
// #include <nrdbase/Base64.h>
// #include <nrdbase/UrlEncoder.h>
// #include <nrdbase/ObjectCount.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <iterator>

using namespace netflix::base;

void DataBuffer::countStats(int /* count */)
{
    // ObjectCount::count("DataBuffer::Capacity", count);
}

// DataBuffer::Data::Data()
//     : data(0), size(0), capacity(0), ownsData(true)
// {
//     // ObjectCount::ref("DataBuffer");
// }

DataPool::Chunk::Chunk()
{

}

DataPool::Chunk::~Chunk()
{

}

void DataPool::Chunk::resize(int size)
{

}

void DataPool::Chunk::free()
{

}


// DataBuffer::Data::~Data()
// {
//     if (data && ownsData) {
//         // ObjectCount::count("DataBuffer::Capacity", -(capacity + 1));
//         free(data);
//     }
//     // ObjectCount::deref("DataBuffer");
// }

// std::string DataBuffer::toBase64String() const
// {
//     std::string result;
//     result.reserve(Base64::encode_reserve(size()));
//     const char * source(data<const char*>());
//     Base64::encode(source, source + size(), std::back_inserter(result));
//     return result;
// }


// DataBuffer DataBuffer::compress(CompressionMode mode, bool *ok) const
// {
//     bool success = false;
//     DataBuffer ret;
//     switch (mode) {
//     case Compression_Normal:
//         success = (StringCompressor::deflate(ret, *this) == NFErr_OK);
//         break;
//     case Compression_GZip:
//         success = (StringCompressor::deflateGzip(ret, *this) == NFErr_OK);
//         break;
//     case Compression_Base64:
//         success = (StringCompressor::deflateB64(ret, *this) == NFErr_OK);
//         break;
//     }
//     if (ok)
//         *ok = success;
//     return ret;
// }

// DataBuffer DataBuffer::uncompress(CompressionMode mode, bool *ok) const
// {
//     DataBuffer ret;
//     bool success = false;
//     switch (mode) {
//     case Compression_Normal:
//         success = (StringCompressor::inflate(ret, *this) == NFErr_OK);
//         break;
//     case Compression_GZip:
//         success = (StringCompressor::inflateGzip(ret, *this) == NFErr_OK);
//         break;
//     case Compression_Base64:
//         success = (StringCompressor::inflateB64(ret, *this) == NFErr_OK);
//         break;
//     }
//     if (ok)
//         *ok = success;
//     return ret;
// }

// DataBuffer DataBuffer::encode(Encoding encoding) const
// {
//     const char hex[] = "0123456789ABCDEF";
//     switch (encoding) {
//     case Encoding_Base64: return Base64::encode(*this);
//     case Encoding_Url: return UrlEncoder::encode<DataBuffer>(data<const char*>(), size());
//     case Encoding_Hex: {
//         int s = size();
//         DataBuffer ret(s * 2);
//         ret.setUsed(s * 2);
//         const unsigned char *in = data();
//         unsigned char *out = ret.data();
//         while (s--) {
//             *out++ = hex[(*in) >> 4];
//             *out++ = hex[(*in) & 0x0F];
//             ++in;
//         }

//         return ret; }
//     }
//     return DataBuffer();
// }

// DataBuffer DataBuffer::decode(Encoding encoding) const
// {
//     switch (encoding) {
//     case Encoding_Base64: return Base64::decode(*this);
//     case Encoding_Url: return UrlEncoder::decode<DataBuffer>(data<const char*>(), size());
//     case Encoding_Hex: {
//         int s = size();
//         if (s % 2 != 0)
//             return DataBuffer();
//         DataBuffer ret(s / 2);
//         ret.setUsed(s / 2);
//         const unsigned char *in = data();
//         unsigned char *out = ret.data();
//         while (s--) {
//             int val;
//             switch (*in++) {
//             case '0': val = 0; break;
//             case '1': val = 1; break;
//             case '2': val = 2; break;
//             case '3': val = 3; break;
//             case '4': val = 4; break;
//             case '5': val = 5; break;
//             case '6': val = 6; break;
//             case '7': val = 7; break;
//             case '8': val = 8; break;
//             case '9': val = 9; break;
//             case 'A':
//             case 'a': val = 10; break;
//             case 'B':
//             case 'b': val = 11; break;
//             case 'C':
//             case 'c': val = 12; break;
//             case 'D':
//             case 'd': val = 13; break;
//             case 'E':
//             case 'e': val = 14; break;
//             case 'F':
//             case 'f': val = 15; break;
//             default: return DataBuffer();
//             }
//             if (s % 2 == 0) {
//                 *out += val;
//                 ++out;
//             } else {
//                 *out = (val << 4);

//             }

//         }
//         return ret; }
//     }
//     return DataBuffer();
// }

DataBuffer DataBuffer::hash(Hash hash, bool *ok) const
{
    if (ok)
        *ok = true;
    DataBuffer ret;
    if (!isEmpty()) {
        switch (hash) {
        case Hash_SHA1: {
            SHA_CTX ctx;
            if (!SHA1_Init(&ctx)) {
                if (ok)
                    *ok = false;
                break;
            }
            if (!SHA1_Update(&ctx, data<const char*>(), size())) {
                unsigned char buf[SHA_DIGEST_LENGTH];
                SHA1_Final(buf, &ctx);
                if (ok)
                    *ok = false;
                break;
            }
            ret.reserve(SHA_DIGEST_LENGTH);
            ret.setUsed(SHA_DIGEST_LENGTH);
            if (!SHA1_Final(ret.data(), &ctx)) {
                if (ok)
                    *ok = false;
                ret.clear();
            }
            break; }
        case Hash_SHA256: {
            SHA256_CTX ctx;
            if (!SHA256_Init(&ctx)) {
                if (ok)
                    *ok = false;
                break;
            }
            if (!SHA256_Update(&ctx, data<const char*>(), size())) {
                unsigned char buf[SHA_DIGEST_LENGTH];
                SHA256_Final(buf, &ctx);
                if (ok)
                    *ok = false;
                break;
            }
            ret.reserve(SHA256_DIGEST_LENGTH);
            ret.setUsed(SHA256_DIGEST_LENGTH);
            if (!SHA256_Final(ret.data(), &ctx)) {
                if (ok)
                    *ok = false;
                ret.clear();
            }
            break; }
        case Hash_MD5: {
            MD5_CTX ctx;
            if (!MD5_Init(&ctx)) {
                if (ok)
                    *ok = false;
                break;
            }
            if (!MD5_Update(&ctx, data<const char*>(), size())) {
                unsigned char buf[SHA_DIGEST_LENGTH];
                MD5_Final(buf, &ctx);
                if (ok)
                    *ok = false;
                break;
            }
            ret.reserve(MD5_DIGEST_LENGTH);
            ret.setUsed(MD5_DIGEST_LENGTH);
            if (!MD5_Final(ret.data(), &ctx)) {
                if (ok)
                    *ok = false;
                ret.clear();
            }
            break; }

        }
    }
    return ret;
}

#if NF_DATABUFFER_RECORD_OUTSTANDING == 1
#include "ScopedMutex.h"
static Mutex sDataRecordMutex(netflix::UNTRACKED_MUTEX, "DataBufferRecord");
int DataBuffer::Data::sCount = 0;
int DataBuffer::Data::sCapacity = 0;
int DataBuffer::Data::sHighCapacity = 0;
void DataBuffer::Data::record(int capacity, int create)
{
    ScopedMutex _lock(sDataRecordMutex);
    assert(create >= -1 && create <= 1);
    sCount += create;
    sCapacity += capacity;
    sHighCapacity = std::max(sHighCapacity, sCapacity);
}
void DataBuffer::recordStats(int *count, int *capacity, int *highCapacity)
{
    ScopedMutex _lock(sDataRecordMutex);
    if(count)
        *count = Data::sCount;
    if(capacity)
        *capacity = Data::sCapacity;
    if(highCapacity)
        *highCapacity = Data::sHighCapacity;
}
#endif
