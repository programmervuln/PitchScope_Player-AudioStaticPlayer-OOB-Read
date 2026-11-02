#include <cstdio>
#include <cstdlib>
#include <cstring>

struct BitSourceStatic
{
    char* m_staticBits;
    long m_totalBytes;

    BitSourceStatic() : m_staticBits(nullptr), m_totalBytes(0) {}
    ~BitSourceStatic()
    {
        if(m_staticBits) free(m_staticBits);
    }

    bool Alloc_Static_Block(long numBytes)
    {
        if(m_staticBits) free(m_staticBits);
        m_staticBits = (char*)malloc(numBytes);
        m_totalBytes = numBytes;
        if(!m_staticBits)
        {
            m_totalBytes = 0;
            return false;
        }
        memset(m_staticBits, 0x41, numBytes);
        return true;
    }
};

struct AudioStaticPlayer
{
    BitSourceStatic* m_bitSource;

    AudioStaticPlayer() : m_bitSource(nullptr) {}

    // Modified: move FORWARD past buffer end instead of backward underflow
    void Load_Next_Data_Forward_OOB(long sampleCount, long startOffset)
    {
        if(!m_bitSource || !m_bitSource->m_staticBits)
            return;

        char* dstData = (char*)malloc(sampleCount * 4);
        char* srcData = m_bitSource->m_staticBits + startOffset;

        for(long k = 0; k < sampleCount; k++)
        {
            *dstData = *srcData;
            dstData++;
            srcData++; // increment to go past buffer end, hits ASAN redzone
        }
        free(dstData);
    }
};

int main()
{
    AudioStaticPlayer player;
    BitSourceStatic* bitSrc = new BitSourceStatic();

    bitSrc->Alloc_Static_Block(16);
    player.m_bitSource = bitSrc;

    // start at offset 0, read 32 bytes, buffer only 16 bytes → post-chunk OOB READ
    player.Load_Next_Data_Forward_OOB(32, 0);

    delete bitSrc;
    return 0;
}

