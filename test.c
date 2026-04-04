#include <stdio.h>
#include <string.h>

#include <curl/curl.h>
#include <time.h>


#include "../../set1/Challenge2/xorHelper.c"

// signature:
// 0x7af51ee0e84bc075c85833faf01619b7dc920dde


size_t silence_callback(void *ptr, size_t size, size_t nmemb, void *data) {
    return size * nmemb;
}

long long getTimeMs() {
    struct timespec ts;
    // CLOCK_MONOTONIC is best for elapsed time
    clock_gettime(CLOCK_MONOTONIC, &ts);
    
    // Convert seconds to ms and nanoseconds to ms
    return (long long)ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);
}

long executeRequest(unsigned char* HMAC, long long *elapsedTime){
    // Build request
    unsigned char* url = malloc(96);
    if(!url){return 1;}
    memcpy(url, "http://localhost:9000/test?file=testfile.txt&signature=", 55);
    unsigned char* HMAC_Hex = malloc(41);
    if(!HMAC_Hex){return 1;}
    for(int i=0;i<20;i++){
        sprintf(HMAC_Hex + (i * 2), "%02x", HMAC[i]);
    }
    memcpy(url+55, HMAC_Hex, 41);

    // Send request to local server and return the status code
    CURL* curlHandle;
    CURLcode res;

    curlHandle = curl_easy_init();

    if(curlHandle){
        curl_easy_setopt(curlHandle, CURLOPT_URL, url);

        curl_easy_setopt(curlHandle, CURLOPT_WRITEFUNCTION, silence_callback);

        long long start = getTimeMs();
        res = curl_easy_perform(curlHandle);
        long long end = getTimeMs();

        *elapsedTime = end - start;

        long responseCode = 0;

        if(res == CURLE_OK){

            curl_easy_getinfo(curlHandle, CURLINFO_RESPONSE_CODE, &responseCode);

            curl_easy_cleanup(curlHandle);

            return responseCode;

        } else {
            curl_easy_cleanup(curlHandle);
            return 0;
        }
    }
}


// Test that the C code speaks to the python server and returns 200 when 
// the signature is correct and 403 when it's not
void test1(){
    char hexString[41] = "7af51ee0e84bc075c85833faf01619b7dc920dde";
    int rawStringLength = 20;
    unsigned char* result = malloc(rawStringLength);
    result = hexStringToRawString(hexString, result);
    long long elapsedTime1 = 0;
    long requestStatus = executeRequest(result, &elapsedTime1);

    char hexString2[41] = "7af51ee0e84bc075c85833faf01619b7dc920ddf";
    unsigned char* result2 = malloc(rawStringLength);
    result2 = hexStringToRawString(hexString2, result2);
    long long elapsedTime2 = 0;
    long requestStatus2 = executeRequest(result2, &elapsedTime2);

    return;
}

// Test what are the mean times for 403 and 200 statuses
// Found out that the mean was:
// 1007 ms for status 200
//   27 ms for status 403 failing on the first byte
//   78 ms for status 403 testing first byte and fails on second byte
void testForMeanTime403and200(){

    //----------------Status 403 string: ------------------------------
    //---------------- Only testing the first byte
    char hexString[41] = "def51ee0e84bc075c85833faf01619b7dc920dde";
    int rawStringLength = 20;
    unsigned char* result = malloc(rawStringLength);
    result = hexStringToRawString(hexString, result);

    long long elapsed403Times[5];
    for(int i=0;i<5;i++){
        executeRequest(result, &elapsed403Times[i]);
    }

    double elapsed403MilisecondsMean = 0;

    for(int i=0;i<5;i++){
        elapsed403MilisecondsMean+=(double) elapsed403Times[i];
    }
    elapsed403MilisecondsMean = elapsed403MilisecondsMean/(double)5;

    //---------------- Testing the first and second bytes
    char hexString3[41] = "7ade1ee0e84bc075c85833faf01619b7dc920dde";
    unsigned char* result3 = malloc(rawStringLength);
    result3 = hexStringToRawString(hexString3, result3);

    long long elapsed403SecondByteTimes[5];
    for(int i=0;i<5;i++){
        executeRequest(result3, &elapsed403SecondByteTimes[i]);
    }

    double elapsed403SecondByteMilisecondsMean = 0;

    for(int i=0;i<5;i++){
        elapsed403SecondByteMilisecondsMean+=(double) elapsed403SecondByteTimes[i];
    }
    elapsed403SecondByteMilisecondsMean = elapsed403SecondByteMilisecondsMean/(double)5;

    //---------------- Testing up to the third byte, failing on the fourth
    char hexString4[41] = "7af51eefe84bc075c85833faf01619b7dc920dde";
    unsigned char* result4 = malloc(rawStringLength);
    result4 = hexStringToRawString(hexString4, result4);

    long long elapsed403ThirdByteTimes[5];
    for(int i=0;i<5;i++){
        executeRequest(result4, &elapsed403ThirdByteTimes[i]);
    }

    double elapsed403ThirdByteMilisecondsMean = 0;

    for(int i=0;i<5;i++){
        elapsed403ThirdByteMilisecondsMean+=(double) elapsed403ThirdByteTimes[i];
    }
    elapsed403ThirdByteMilisecondsMean = elapsed403ThirdByteMilisecondsMean/(double)5;

    //----------------Status 200 string: ------------------------------

    char hexString2[41] = "7af51ee0e84bc075c85833faf01619b7dc920dde";
    int rawStringLength2 = 20;
    unsigned char* result2 = malloc(rawStringLength2);
    result2 = hexStringToRawString(hexString2, result2);
    
    long long elapsed200Times[5];
    for(int i=0;i<5;i++){
        executeRequest(result2, &elapsed200Times[i]);
    }

    double elapsed200MilisecondsMean = 0;

    for(int i=0;i<5;i++){
        elapsed200MilisecondsMean+=(double) elapsed200Times[i];
    }
    elapsed200MilisecondsMean = elapsed200MilisecondsMean/(double)5;
    return;
}

// signature:
// 0x7a f5 1e e0 e8 4b c0 75 c8 58 33 fa f0 16 19 b7 dc 92 0d de

// TODO: test the same character 100 times and get the average
// instead of the elapsedTime use the average and select the maximum average
int SHA1_DIGEST_SIZE = 20;
unsigned char* break_HMACSHA1_with_side_channel(){

    unsigned char* craftedMAC = calloc(SHA1_DIGEST_SIZE, 1);
    for(int i=0;i<SHA1_DIGEST_SIZE;i++){
        double averageElapsedTimes[256];
        for(unsigned int c=0;c<256;c++){
            craftedMAC[i] = c & 0xff;
            //printf("i: %i | c: %02x\n", i, c);
            long long totalElapsedTime = 0;
            long responseStatus = 0;
            for(int j=0;j<25;j++){
                long long currentElapsedTime = 0;
                responseStatus = executeRequest(craftedMAC, &currentElapsedTime);
                totalElapsedTime += currentElapsedTime;
            }
            double averageElapsedTime = totalElapsedTime/(double) 25;
            averageElapsedTimes[c] = averageElapsedTime;
            
            if(responseStatus == 200){
                return craftedMAC;
            }
        }

        long long maxElapsedTime = averageElapsedTimes[0];
        unsigned char maxElapsedTimeChar = 0;
        for(int c=0;c<256;c++){
            if(averageElapsedTimes[c] > maxElapsedTime){
                maxElapsedTime = averageElapsedTimes[c];
                maxElapsedTimeChar = (unsigned char) c;
            }
        }
        craftedMAC[i] = maxElapsedTimeChar;
        printf("found byte: %02x\n", maxElapsedTimeChar);
    }
    return NULL;
}

int main(){

    //test1();
    //testForMeanTime403and200();
    
    unsigned char* brokenMAC = break_HMACSHA1_with_side_channel();
    for(int i=0;i<20;i++){
        printf("%02x",brokenMAC[i]);
    }
    printf("\n");

    return 0;
}