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

#ifdef BAZEL_BUILD
#include "examples/protos/helloworld.grpc.pb.h"
#else
#include "helloworld.grpc.pb.h"
#endif

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
 
  wg_endpoint e;
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(50051);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  e.addr4 = addr;

  wg_key peer_key;
  //wg_key_b64_string pkey = {0};
  wg_key_b64_string pkey = {'m','2','m','0','3','m','i','J','w','g','e',
	  'N','v','B','B','1','K','o','P','o','s','g','R','b','A','c','+',
	  'p','l','+','e','G','f','e','s','4','x','6','K','N','v','l','c','='};
  wg_key_from_base64(peer_key, pkey);

  wg_key_b64_string pskey = {'9','H','Z','v','6','Z','K','6',
                  'O','7','h','k','s','+','S','1','w','a','u','t','x','t',
                  'w','n','g','7','Y','Q','u','/','R','q','q','3','2','X',
                  'z','i','T','a','+','y','A','='};
  
  wg_peer new_peer = {
	.flags = (wg_peer_flags) (WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS),
	.endpoint = e
  };
  wg_key_from_base64(new_peer.public_key, pkey); 
  wg_key_from_base64(new_peer.preshared_key,pskey); 

  wg_device new_device = {
	.name = "wgtest0",
	.flags = (wg_device_flags)(WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_HAS_LISTEN_PORT),
	.listen_port = 12345,
	.first_peer = &new_peer,
	.last_peer = &new_peer
  };

/*  
  wg_key temp_private_key;
  wg_generate_private_key(temp_private_key);
  wg_generate_public_key(new_peer.public_key, temp_private_key);
*/

  wg_key_b64_string key, key2;
  wg_key_to_base64(key, new_peer.public_key);
 // printf("peer pub key %s\n", key);
  
  wg_generate_private_key(new_device.private_key);
  wg_key_to_base64(key2, new_device.private_key);
 // printf("device pri key %s\n", key2);
  
  if (wg_add_device(new_device.name) < 0) {
	perror("Unable to add device");
	exit(1);
  }

  if (wg_set_device(&new_device) < 0) {
	perror("Unable to set device");
	exit(1);
  }

  list_devices();

  if (wg_del_device(new_device.name) < 0) {
	perror("Unable to delete device");
	exit(1);
  }
  return 0;
}
