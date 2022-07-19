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

extern "C" {
  #include "wireguard.h"
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <arpa/inet.h>
}

#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#ifdef BAZEL_BUILD
#include "examples/protos/helloworld.grpc.pb.h"
#else
#include "helloworld.grpc.pb.h"
#endif

std::string device_name = "wgtest0s";
using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using helloworld::Greeter;
using helloworld::HelloReply;
using helloworld::HelloRequest;

// Logic and data behind the server's behavior.
class GreeterServiceImpl final : public Greeter::Service {
  Status SayHello(ServerContext* context, const HelloRequest* request,
                  HelloReply* reply) override {
    std::string prefix("Hello ");
    reply->set_message(prefix + request->name());
    return Status::OK;
  }

  Status SayHelloAgain(ServerContext* context, const HelloRequest* request,
                       HelloReply* reply) override {
    std::string prefix("Hello again ");
    reply->set_message(prefix + request->name());
    return Status::OK;
  }
};

void RunServer() {
  std::string server_address("192.168.44.1:50051");
  GreeterServiceImpl service;

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();
  ServerBuilder builder;
  // Listen on the given address without any authentication mechanism.
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  // Register "service" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *synchronous* service.
  builder.RegisterService(&service);
  // Finally assemble the server.
  std::unique_ptr<Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << server_address << std::endl;

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
}

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

    wg_key_b64_string pskey = {'2','3','/','3','x','p','m','K',
        'z','E','C','u','J','q','6','7','z','C','r','X','E','T','2',
        'E','g','s','P','K','C','O','e','c','Z','/','j','c','x','+',
        '1','n','A','h','s','='};

    wg_key_b64_string prkey = {'+','K','v','1','R','d','7','S','T','G','S','G',
        'F','j','C','y','2','J','/','e','Z','X','U','s','L','S','u','7',
        'N','K','O','q','O','U','c','w','e','C','P','8','i','k','s','='};

    wg_key_b64_string pukey = {'s','u','C','E','y','8','u','4','r','x','y','d',
        '5','2','3','h','C','o','0','m','q','+','u','L','7','p','n','8','M',
        'w','K','s','p','L','w','H','q','B','C','J','r','S','A','='};

    wg_key_b64_string ppukey = {'v','8','L','p','Z','m','2','y','q','I','X','i',
        's','8','9','2','C','M','j','q','C','3','D','I','R','Y','Z','t','J',
        '7','t','S','V','4','I','o','d','M','A','c','P','V','c','='};

    wg_endpoint e;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12346);
    // 192.168.143.212 0xc0a88fd4
    addr.sin_addr.s_addr = htonl(0x2d4d64bc); //INADDR_LOOPBACK);
    e.addr4 = addr;

    //allowed ip
    wg_allowedip allowedip;
    allowedip.family = AF_INET;
   inet_aton("192.168.44.2", &allowedip.ip4);
    allowedip.cidr = 31;


    wg_peer new_peer = {
        .flags = (wg_peer_flags) (WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS | WGPEER_HAS_PRESHARED_KEY),
        .endpoint = e,
        .first_allowedip = &allowedip,
        .last_allowedip = &allowedip,
    };
    wg_key_from_base64(new_peer.public_key, ppukey);
    wg_key_from_base64(new_peer.preshared_key,pskey);


    /*
    wg_device new_device = {
        .name = device_name,
        .flags = (wg_device_flags)(WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_HAS_LISTEN_PORT),
        .listen_port = 12345,
        .first_peer = &new_peer,
        .last_peer = &new_peer
    };
    */
    wg_device new_device;

    strcpy(new_device.name, device_name.c_str());
    new_device.flags = (wg_device_flags)(WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_HAS_LISTEN_PORT);
    new_device.listen_port = 12345;
    new_device.first_peer = &new_peer;
    new_device.last_peer = &new_peer;
    wg_key_from_base64(new_device.public_key, pukey);
    wg_key_from_base64(new_device.private_key, prkey);

    /*
       wg_key temp_private_key;
       wg_generate_private_key(temp_private_key);
       wg_generate_public_key(new_peer.public_key, temp_private_key);
       wg_generate_private_key(new_device.private_key);
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

    RunServer();

    return 0;
}
