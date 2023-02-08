/*
 This file is part of JustGarble.

 JustGarble is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 JustGarble is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with JustGarble.  If not, see <http://www.gnu.org/licenses/>.

 */
/*
 This file is part of TinyGarble. It is modified version of JustGarble
 under GNU license.

 TinyGarble is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 TinyGarble is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with TinyGarble.  If not, see <http://www.gnu.org/licenses/>.
 */
//#include "util.h"
#include "tinygarble_config.h"
#include "log.h"
#include <boost/program_options.hpp>
#include <boost/format.hpp>
#include <cstdlib>
#include <ctime>
#include "emp-tool/emp-tool.h"
//#include "crypto/OT_extension.h"
#include "garbled_circuit.h"
//#include "scd/scd.h"
//#include "tcpip/tcpip.h"
#include <chrono>

namespace po = boost::program_options;
using std::string;
using std::vector;

int main(int argc, char* argv[]) {

  LogInitial(argc, argv);
  
 	int length = 1;
block *b0 = new block[length];
block *b1 = new block[length];
block *r = new block[length];
	PRG prg(fix_key);

prg.random_block(b0, length);
prg.random_block(b1, length);
	bool *b = new bool[length];
	PRG prg2;
 prg2.random_bool(b, length);
int party;
//NetIO *io;
  int port;
  string scd_file_address;
  string server_ip;
  string p_init_f_hex_str;
  string p_input_f_hex_str;
  string init_f_hex_str;
  string input_f_hex_str;
  string input_f_hex_str_bob;
  int64_t terminate_period;
  uint64_t clock_cycles;
  string output_mask;
  string output_mode_str;
  OutputMode output_mode = OutputMode::consecutive;
  bool disable_OT = false;
  bool low_mem_foot = false;
  boost::format fmter(
      "Garble and Evaluate Netlist, TinyGarble version %1%.%2%.%3%.\nAllowed options");
  fmter % TinyGarble_VERSION_MAJOR % TinyGarble_VERSION_MINOR
      % TinyGarble_VERSION_PATCH;
  po::options_description desc(fmter.str());
  desc.add_options()  //
  ("help,h", "produce help message")  //
  ("alice,a", "Run as Alice (server).")  //
  ("bob,b", "Run as Bob (client).")  //
  ("scd_file,i",
   po::value<string>(&scd_file_address)->default_value(
       "/scd/netlists/hamming_32bit_1cc.scd"),
   "Simple circuit description (.scd) file address.")  //
  ("port,p", po::value<int>(&port)->default_value(1234), "socket port")  //
  ("server_ip,s", po::value<string>(&server_ip)->default_value("127.0.0.1"),
   "Server's (Alice's) IP, required when running as Bob.")  //
  ("p_init", po::value<string>(&p_init_f_hex_str)->default_value("0"),
   "File or Hexadecimal public init for initializing DFFs. In case of file,"
   " each line should contain multiple of 4 bits (e.g., 4bit, 8bit, 32bit).")  //
  ("p_input", po::value<string>(&p_input_f_hex_str)->default_value("0"),
   "File or Hexadecimal public input.")  //
  ("init", po::value<string>(&init_f_hex_str)->default_value("0"),
   "Hexadecimal init for initializing DFFs.")  //
  ("input", po::value<string>(&input_f_hex_str)->default_value("0"),
   "File or Hexadecimal input.")
    ("inputbob", po::value<string>(&input_f_hex_str_bob)->default_value("0"),
   "File or Hexadecimal input.")   //
  ("clock_cycles,c", po::value<uint64_t>(&clock_cycles)->default_value(1),
   "Number of clock cycles to evaluate the circuit.")  //
  ("dump_directory", po::value<string>(&dump_prefix)->default_value(""),
   "Directory for dumping memory hex files.")  //
  ("disable_OT", "Disables Oblivious Transfer (OT) for transferring labels. "
   "WARNING: OT is crucial for GC security.")  //
  ("low_mem_foot", "Enables low memory footprint mode for circuits with "
   "multiple clock cycles. In this mode, OT is called at each clock cycle "
   "which degrades the performance.")  //
  ("output_mask", po::value<string>(&output_mask)->default_value("0"),
   "Hexadecimal mask for output. 0 indicates that output belongs to Bob, "
   "and 1 belongs to Alice. It has the same length of the output for a "
   "single clock in case of sequential circuits.")  //
  ("terminate_period,t",
   po::value<int64_t>(&terminate_period)->default_value(0),
   "Terminate signal reveal period: "
   "0: No termination or never reveal, T: Reveal every T clock cycle.")  //
  ("output_mode", po::value<string>(&output_mode_str),
   "output print mode: {0:consecutive, 1:separated_clock, "
   "2:last_clock}, e.g., consecutive, 0, 1");

  po::variables_map vm;
  try {
    po::parsed_options parsed = po::command_line_parser(argc, argv).options(
        desc).allow_unregistered().run();
    po::store(parsed, vm);
    if (vm.count("help")) {
      std::cout << desc << endl;
      return SUCCESS;
    }
    po::notify(vm);
  } catch (po::error& e) {
    LOG(ERROR) << "ERROR: " << e.what() << endl << endl;
    std::cout << desc << endl;
    return FAILURE;
  }

  if (vm.count("output_mode")) {
    if (vm["output_mode"].as<string>() == "0"
        || vm["output_mode"].as<string>() == "consecutive") {
      output_mode = OutputMode::consecutive;
    } else if (vm["output_mode"].as<string>() == "1"
        || vm["output_mode"].as<string>() == "separated_clock") {
      output_mode = OutputMode::separated_clock;
    } else if (vm["output_mode"].as<string>() == "2"
        || vm["output_mode"].as<string>() == "last_clock") {
      output_mode = OutputMode::last_clock;
    } else {
      LOG(ERROR) << "ERROR: output_mode should be in "
                 "{0:consecutive, 1:separated_clock, 2:last_clock}"
                 << endl;
      std::cout << desc << endl;
      return FAILURE;
    }
  }

  if (vm.count("low_mem_foot")) {
    low_mem_foot = true;
    LOG(INFO) << "Low memory footprint mode is on." << endl;
  }

 // if (vm.count("alice") == 0 && vm.count("bob") == 0) {
 //   LOG(ERROR) << "One of --alice or --bob mode flag should be used." << endl
  //             << endl;
  //  std::cout << desc << endl;
  //  return FAILURE;
 // }

  // Transferring file in to hex
  string p_init_str = ReadFileOrPassHex(p_init_f_hex_str);
  string p_input_str = ReadFileOrPassHex(p_input_f_hex_str);
  string init_str = ReadFileOrPassHex(init_f_hex_str);
  string input_str = ReadFileOrPassHex(input_f_hex_str);
  string input_str_bob = ReadFileOrPassHex(input_f_hex_str_bob);

const char* chr = server_ip.c_str();
cout<<"Address is "<<chr<<endl;
cout<<"port is " <<port<<endl;
 // if (vm.count("alice")) {
  

 //   	 NetIO *io = new NetIO(party == ALICE?nullptr:chr,port);
//FerretCOT<NetIO> * ferretcot = new FerretCOT<NetIO>(party, 1, &io, false,true,ferret_b13,"preot/pre_ot_data_reg_send");
  // IKNP<NetIO> * ferretcot = new IKNP<NetIO>(io);

  //    ferretcot->send(b0,b1,length);
             	//io->flush();
	//io->sync();

 cout << "Open Alice's server on port: " << port << endl;

                  

    string output_str_alice;
    string output_str_bob;
    uint64_t delta_time = RDTSC;
        uint64_t delta_timebob = RDTSC;
auto begin = std::chrono::high_resolution_clock::now();
        GarbleStr(scd_file_address, p_init_str, p_input_str, init_str,
                  input_str,input_str_bob, clock_cycles, output_mask, terminate_period,
                  output_mode, disable_OT, low_mem_foot, &output_str_alice,&output_str_bob);
    delta_time = RDTSC - delta_time;

   cout  << "Alice's output = " << output_str_alice << endl;
    cout  << "Total Alice time (cc) = " << delta_time << endl;
    std::cout << output_str_alice << endl;
  //delete io;
 auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    
  //  printf("Result: %.20f\n", sum);
    
    printf("Time measured: %.3f mseconds.\n", elapsed.count() * 1e-3);
//  delete ferretcot;
//  } else if (vm.count("bob")) {

   // if (vm.count("server_ip")) {
     // server_ip = vm["server_ip"].as<string>();
    //} else {
      //LOG(ERROR) << "Server IP should be specified, when running as Bob."
        //         << endl << endl;
      //std::cout << desc << endl;
      //return -1;
   // }

  


    //	 NetIO *io = new NetIO(party == ALICE?nullptr:chr,port);
//FerretCOT<NetIO> * ferretcot = new FerretCOT<NetIO>(party, 1, &io, false,true,ferret_b13,"preot/pre_ot_data_reg_recv");
      // IKNP<NetIO> * ferretcot = new IKNP<NetIO>(io);

  //     ferretcot->recv(r,b,length);
    //  	io->sync();
// 	io->flush();

   //cout << "Connect Bob's client to Alice's server on " << server_ip
     //         << ":" << port << endl;

 
    //string output_str_bob;
   // uint64_t delta_time = RDTSC;
      //  EvaluateStr(scd_file_address, p_init_str, p_input_str, init_str,
        //            input_str, clock_cycles, output_mask, terminate_period,
        //          output_mode, disable_OT, low_mem_foot, &output_str_bob);
    delta_timebob = RDTSC - delta_timebob;

cout  << "Bob's output = " << output_str_bob << endl;
    cout  << "Total Bob time (cc) = " << delta_timebob << endl;
    std::cout << output_str_bob << endl;
  //  delete io;

//  delete ferretcot;

//  }
delete[] b0;
	delete[] b1;
	delete[] r;
	delete[] b;
  //delete io;
  LogFinish();
  return SUCCESS;
}

