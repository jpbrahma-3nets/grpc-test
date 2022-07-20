/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>
extern "C"{
#include "wireguard.h"
#include <netinet/in.h>
#include <sys/socket.h>
}
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#ifdef BAZEL_BUILD
#include "examples/protos/helloworld.grpc.pb.h"
#else
#include "helloworld.grpc.pb.h"
#endif

std::string device_name = "wgtest0c";
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using helloworld::Greeter;
using helloworld::HelloReply;
using helloworld::HelloRequest;

class GreeterClient {
 public:
  GreeterClient(std::shared_ptr<Channel> channel)
      : stub_(Greeter::NewStub(channel)) {}

  // Assembles the client's payload, sends it and presents the response back
  // from the server.
  std::string SayHello(const std::string& user) {
    // Data we are sending to the server.
    HelloRequest request;
    request.set_name(user);

    // Container for the data we expect from the server.
    HelloReply reply;

    // Context for the client. It could be used to convey extra information to
    // the server and/or tweak certain RPC behaviors.
    ClientContext context;

    // The actual RPC.
    Status status = stub_->SayHello(&context, request, &reply);

    // Act upon its status.
    if (status.ok()) {
      return reply.message();
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return "RPC failed";
    }
  }

  std::string SayHelloAgain(const std::string& user) {
    // Follows the same pattern as SayHello.
    HelloRequest request;
    request.set_name(user);
    HelloReply reply;
    ClientContext context;

    // Here we can use the stub's newly available method we just added.
    Status status = stub_->SayHelloAgain(&context, request, &reply);
    if (status.ok()) {
      return reply.message();
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return "RPC failed";
    }
  }

 private:
  std::unique_ptr<Greeter::Stub> stub_;
};

void list_devices(void)
{
    char *device_names, *device_name;
    size_t len;

    device_names = wg_list_device_names();
    if (!device_names) {
        perror("Unable to get device names");
        exit(1);
    }
    wg_for_each_device_name(device_names, device_name, len) {
        wg_device *device;
        wg_peer *peer;
        wg_key_b64_string key;

        if (wg_get_device(&device, device_name) < 0) {
            perror("Unable to get device");
            continue;
        }
        if (device->flags & WGDEVICE_HAS_PUBLIC_KEY) {
            wg_key_to_base64(key, device->public_key);
            printf("%s has public key %s\n", device_name, key);
        } else
            printf("%s has no public key\n", device_name);
        wg_for_each_peer(device, peer) {
            wg_key_to_base64(key, peer->public_key);
            printf(" - peer %s\n", key);
        }
        wg_free_device(device);
    }
    free(device_names);
}

int check_device(const char * device_name_to_check) {
    char *device_names, *device_name;
    size_t len;

    device_names = wg_list_device_names();
    if (!device_names) {
        perror("Unable to get device names");
        exit(1);
    }

    wg_for_each_device_name(device_names, device_name, len) {
        if (strcmp(device_name, device_name_to_check) == 0) 
            return 1;
    }
    return 0;
}


int main(int argc, char** argv) {
    // Instantiate the client. It requires a channel, out of which the actual RPCs
    // are created. This channel models a connection to an endpoint specified by
    // the argument "--target=" which is the only expected argument.
    // We indicate that the channel isn't authenticated (use of
    // InsecureChannelCredentials()).
    std::string target_str;
    std::string arg_str("--target");
    if (argc > 1) {
        std::string arg_val = argv[1];
        size_t start_pos = arg_val.find(arg_str);
        if (start_pos != std::string::npos) {
            start_pos += arg_str.size();
            if (arg_val[start_pos] == '=') {
                target_str = arg_val.substr(start_pos + 1);
            } else {
                std::cout << "The only correct argument syntax is --target="
                    << std::endl;
                return 0;
            }
        } else {
            std::cout << "The only acceptable argument is --target=" << std::endl;
            return 0;
        }
    } else {
        target_str = "localhost:50051";
    }
    GreeterClient greeter(
            grpc::CreateChannel(target_str, grpc::InsecureChannelCredentials()));
    std::string user("world");
    std::string reply = greeter.SayHello(user);
    std::cout << "Greeter received: " << reply << std::endl;

    reply = greeter.SayHelloAgain(user);
    std::cout << "Greeter received: " << reply << std::endl;



    //Wireguard code
    wg_endpoint e;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    inet_aton("5.161.133.68", &addr.sin_addr);
    e.addr4 = addr;

    //allowed ip
    wg_allowedip allowedip;
    allowedip.family = AF_INET;
    inet_aton("0.0.0.0", &allowedip.ip4);
    allowedip.cidr = 0;

    wg_key_b64_string prkey = {'s','J','l','H','Y','f','9','E','J','k','a','S',
        'S','u','X','f','Z','a','s','g','S','T','T','9','r','R','X','j','W',
        'G','M','6','L','w','s','Y','J','b','j','l','K','E','c','='};

    wg_key_b64_string pskey = {'2','3','/','3','x','p','m','K','z','E','C',
        'u','J','q','6','7','z','C','r','X','E','T','2','E','g','s','P',
        'K','C','O','e','c','Z','/','j','c','x','+','1','n','A','h','s','='};

    wg_key_b64_string pukey = {'v','8','L','p','Z','m','2','y','q','I','X',
        'i','s','8','9','2','C','M','j','q','C','3','D','I','R','Y','Z',
        't','J','7','t','S','V','4','I','o','d','M','A','c','P','V','c','='};

    wg_key_b64_string ppukey = {'s','u','C','E','y','8','u','4','r','x','y',
        'd','5','2','3','h','C','o','0','m','q','+','u','L','7','p','n',
        '8','M','w','K','s','p','L','w','H','q','B','C','J','r','S','A','='};

    wg_peer new_peer = {
        .flags = (wg_peer_flags) (WGPEER_HAS_PUBLIC_KEY |
		       	WGPEER_REPLACE_ALLOWEDIPS |
		       	WGPEER_HAS_PRESHARED_KEY |
			WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL),
	.persistent_keepalive_interval = 10,
	.first_allowedip = &allowedip,
	.last_allowedip = &allowedip,
        .endpoint = e
    };
    wg_key_from_base64(new_peer.public_key, ppukey); 
    wg_key_from_base64(new_peer.preshared_key,pskey); 

    wg_device new_device;
    strcpy(new_device.name, device_name.c_str());
    new_device.flags = (wg_device_flags)(WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_HAS_LISTEN_PORT),
    new_device.listen_port = 12346;
    new_device.first_peer = &new_peer;
    new_device.last_peer = &new_peer;
    new_device.ifindex = 11;

    wg_key_from_base64(new_device.public_key, pukey);
    wg_key_from_base64(new_device.private_key, prkey);

    /*  
        wg_key temp_private_key;
        wg_generate_private_key(temp_private_key);
        wg_generate_public_key(new_peer.public_key, temp_private_key);


        wg_key_b64_string key, key2;
        wg_key_to_base64(key, new_peer.public_key);

        wg_generate_private_key(new_device.private_key);
        wg_key_to_base64(key2, new_device.private_key);
        */  


    int device_exists = check_device(device_name.c_str());

    if (!device_exists) {
        if (wg_add_device(new_device.name) < 0) {
            perror("Unable to add device");
            exit(1);
        }

        if (wg_set_device(&new_device) < 0) {
            perror("Unable to set device");
            exit(1);
        }
        printf("got ifindex = %d", new_device.ifindex);
    }

    list_devices();

    /*
       if (wg_del_device(new_device.name) < 0) {
       perror("Unable to delete device");
       exit(1);
       }
       */
    return 0;
}


