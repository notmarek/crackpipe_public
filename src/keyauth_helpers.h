//
// Created by vesel on 03.08.2024.
//

#ifndef LOL_KEYAUTH_HELPERS_H
#define LOL_KEYAUTH_HELPERS_H

#include <vector>
#include <string>

class someKindaString {
public:
    char data[16];
    size_t length;
    size_t extra;

    someKindaString &operator=(const std::string &obj) {
        memcpy(*(char **) this->data, obj.c_str(), obj.length() + 1);
        this->length = obj.length();
        return *this;
    }

    char *c_str() {
        if ((extra ^ 0x0F) == 0) {
            return (char *) data;
        }
        return *reinterpret_cast<char **>(data);
    }
};

struct subscriptions {
    someKindaString name;
    someKindaString expiry;
};

struct channelMessage {
    someKindaString author;
    someKindaString message;
    someKindaString timestamp;
};

struct appdata {
    someKindaString numUsers;
    someKindaString numOnlineUsers;
    someKindaString numKeys;
    someKindaString appdataversion;
    someKindaString customerPanelLink;
};
struct response {
    std::vector<channelMessage> channelData;
    uint8_t success;
    someKindaString message;
};
struct user {
    someKindaString username;
    someKindaString ip;
    someKindaString hwid;
    someKindaString createdate;
    someKindaString lastlogin;
    std::vector<subscriptions> subs;
};
struct api {
    someKindaString name;
    someKindaString ownerid;
    someKindaString secret;
    someKindaString version;
    someKindaString url;
    user user;
    appdata appdata;
    response response;
    someKindaString sessionId;
    someKindaString sessionSecret;
};
#endif //LOL_KEYAUTH_HELPERS_H
