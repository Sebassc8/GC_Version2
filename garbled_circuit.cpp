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

#include "garbled_circuit.h"
#include "log.h"
#include "common.h"
#include "util.h"
#include "scd/scd.h"
#include "scd/scd_evaluator.h"
//#include "crypto/aes.h"
//#include "crypto/BN.h"
//#include "crypto/OT.h"
//#include "crypto/OT_extension.h"
#include "garbled_circuit_util.h"
#include "garbled_circuit_high_mem.h"
//#include "garbled_circuit/garbled_circuit_low_mem.h"
//#include "tcpip/tcpip.h"
//#include "util.h"
#include <chrono>
#include <emp-tool/emp-tool.h>
#include "emp-ot/emp-ot.h"
  //GarbledCircuit garbled_circuit;
uint64_t garbled_table_ind = 0;
#define get_LSB(x) (*((unsigned short *)&x)&1)

int GarbleStr(const string& scd_file_address, const string& p_init_str,
              const string& p_input_str, const string& init_str,
              const string& input_str, const string& input_str_bob, uint64_t clock_cycles,
              const string& output_mask, int64_t terminate_period,
              OutputMode output_mode, bool disable_OT, bool low_mem_foot,
              string* output_str,string* output_str_bob) {
  if (clock_cycles == 0) {
    return FAILURE;
  }

  GarbledCircuit garbled_circuit;
  if (ReadSCD(scd_file_address, &garbled_circuit) == FAILURE) {
    std::cout << "Error while reading scd file: " << scd_file_address << endl;
    return FAILURE;
  }
  FillFanout(&garbled_circuit);
 GarbledCircuit garbled_circuitb;
  if (ReadSCD(scd_file_address, &garbled_circuitb) == FAILURE) {
    std::cout << "Error while reading scd file: " << scd_file_address << endl;
    return FAILURE;
  }
  FillFanout(&garbled_circuitb);
  if (terminate_period != 0 && garbled_circuitb.terminate_id == 0) {
    std::cout  << "There is no terminate signal in the circuit."
               " The terminate period should be 0."
               << endl;
    return FAILURE;
  }

   if (terminate_period != 0 && garbled_circuit.terminate_id == 0) {
    std::cout  << "There is no terminate signal in the circuit."
               " The terminate period should be 0."
               << endl;
    return FAILURE;
  }

  block R = RandomBlock();  // secret label
  *((short *) (&R)) |= 1;

  // parse init and input
  BIGNUM* p_init = BN_new();
  BIGNUM* p_input = BN_new();
  BIGNUM* g_init = BN_new();
  BIGNUM* g_input = BN_new();
  BIGNUM* output_bn = BN_new();
  CHECK(
      ParseInitInputStr(init_str, input_str, garbled_circuit.g_init_size,
                        garbled_circuit.g_input_size, clock_cycles, &g_init,
                        &g_input));
  CHECK(
      ParseInitInputStr(p_init_str, p_input_str, garbled_circuit.p_init_size,
                        garbled_circuit.p_input_size, clock_cycles, &p_init,
                        &p_input));

 BIGNUM* p_init_bob = BN_new();
  BIGNUM* p_input_bob = BN_new();
  BIGNUM* e_init = BN_new();
  BIGNUM* e_input = BN_new();
  BIGNUM* output_bn_bob = BN_new();
  CHECK(
      ParseInitInputStr(init_str, input_str_bob, garbled_circuitb.e_init_size,
                        garbled_circuitb.e_input_size, clock_cycles, &e_init,
                        &e_input));
  CHECK(
      ParseInitInputStr(p_init_str, p_input_str, garbled_circuitb.p_init_size,
                        garbled_circuitb.p_input_size, clock_cycles, &p_init_bob,
                        &p_input_bob));

  // global key
  PRG pg;
  block* global_key = new block[sizeof(block)];
  pg.random_block(global_key,sizeof(block));

//	io->sync();


//cout<<"ALice input str: "<<input_str<<endl;
//cout<<"Bob input str: "<<input_str_bob<<endl;

 
 
  block* init_labels = nullptr;
  block* input_labels = nullptr;
  block* output_labels = nullptr;
  short* output_vals = nullptr;

  // allocate init and input values and translate form string
  CHECK(
      GarbleMakeLabels(garbled_circuit, &init_labels, &input_labels,
                       &output_labels, &output_vals, R, clock_cycles));

  block* init_labels_bob = nullptr;
  block* input_labels_bob = nullptr;
  block* output_labels_bob = nullptr;
  short* output_vals_bob = nullptr;

  CHECK(
      EvaluateMakeLabels(garbled_circuitb, &init_labels_bob, &input_labels_bob,
                         &output_labels_bob, &output_vals_bob, clock_cycles));                   
    /*CHECK(
        GarbleBNHighMem(garbled_circuit, p_init, p_input, g_init, g_input,
                       &clock_cycles, output_mask, terminate_period,
                       output_mode, output_bn, R, global_key, disable_OT,
                      io,ferretcot));
    CHECK(  
       OutputBN2StrHighMem(garbled_circuit, output_bn, clock_cycles,
                           output_mode, output_str));
  */

  for (uint i = 0; i < garbled_circuit.g_init_size; i++) {
    if (i >= (uint) BN_num_bits(g_init) || BN_is_bit_set(g_init, i) == 0) {
     init_labels_bob[i]=init_labels[i * 2 + 0];
    } else {
     init_labels_bob[i]=init_labels[i * 2 + 1];
    }
  }
// g_input
  for (uint cid = 0; cid < clock_cycles; cid++) {
    for (uint i = 0; i < garbled_circuit.g_input_size; i++) {
      if (cid * garbled_circuit.g_input_size + i >= (uint) BN_num_bits(g_input)
          || BN_is_bit_set(g_input, cid * garbled_circuit.g_input_size + i)
              == 0) {
    
     input_labels_bob[(cid * garbled_circuitb.get_secret_input_size() + i)]=input_labels[(cid * garbled_circuit.get_secret_input_size() + i)
                    * 2 + 0];
                  //     std::cout<<"alice send 0: "<<input_labels[(cid * garbled_circuit.get_secret_input_size() + i)
                  //  * 2 + 0]<<endl;
                   //  std::cout<<"bob got 0: "<<input_labels_bob[(cid * garbled_circuit.get_secret_input_size() + i)]<<endl;

      } else {
               input_labels_bob[(cid * garbled_circuitb.get_secret_input_size() + i)]=input_labels[(cid * garbled_circuit.get_secret_input_size() + i)
                    * 2 + 1]; 
                 //      std::cout<<"alice send 1: "<<input_labels[(cid * garbled_circuit.get_secret_input_size() + i)
                  //  * 2 + 1]<<endl;
                  //   std::cout<<"bob got 1: "<<input_labels_bob[(cid * garbled_circuit.get_secret_input_size() + i)]<<endl;

      }
    }
  }



auto begin = std::chrono::high_resolution_clock::now();


  uint32_t message_len = garbled_circuit.e_init_size
      + clock_cycles * garbled_circuit.e_input_size;
  block **message = nullptr;
  CHECK_ALLOC(message = new block*[message_len]);
  for (uint i = 0; i < garbled_circuit.e_init_size; i++) {
    CHECK_ALLOC(message[i] = new block[2]);
    for (uint j = 0; j < 2; j++) {
      message[i][j] = init_labels[(i + garbled_circuit.g_init_size) * 2 + j];
    }
  }
  for (uint cid = 0; cid < clock_cycles; cid++) {
    for (uint i = 0; i < garbled_circuit.e_input_size; i++) {
      uint idx = garbled_circuit.e_init_size
          + cid * garbled_circuit.e_input_size + i;
      CHECK_ALLOC(message[idx] = new block[2]);
      for (uint j = 0; j < 2; j++) {
        message[idx][j] = input_labels[(cid
            * garbled_circuit.get_secret_input_size() + i
            + garbled_circuit.g_input_size) * 2 + j];
      }
    }
  }
//PRG pg;
block *b0 = new block[message_len];
block *b1 = new block[message_len];


for (int64_t i = 0; i < message_len; ++i) {

memcpy(&b0[i], &message[i][0], sizeof(b0[i]));
memcpy(&b1[i], &message[i][1], sizeof(b1[i]));

//cout<<"message 0: "<<b0[i]<<endl;
//cout<<"message 1: "<<b1[i]<<endl;

}


  bool *select = nullptr;
  CHECK_ALLOC(select = new bool[message_len]);
  for (uint i = 0; i < garbled_circuitb.e_init_size; i++) {
    select[i] = BN_is_bit_set(e_init, i);
  }
  for (uint cid = 0; cid < clock_cycles; cid++) {
    for (uint i = 0; i < garbled_circuitb.e_input_size; i++) {
      uint indx = garbled_circuitb.e_init_size
          + cid * garbled_circuitb.e_input_size + i;
      select[indx] = BN_is_bit_set(e_input,
                                   cid * garbled_circuitb.e_input_size + i);
    }
  }

  block* rmessage = nullptr;
  CHECK_ALLOC(rmessage = new block[message_len]);
	int length = message_len;
  Group *G = new Group();	
BigInt a;
		Point A, AaInv;
		block res[2];
		Point * B = new Point[length];
		Point * BA = new Point[length];
BigInt * bb = new BigInt[length];
Point * As = new Point[length];


for(int64_t i = 0; i < length; ++i) {
			G->get_rand_bn(bb[i]);
}

		G->get_rand_bn(a);
		A = G->mul_gen(a);
	//	io->send_pt(&A);
  AaInv = A.mul(a);
		AaInv = AaInv.inv();
		
for(int64_t i = 0; i < length; ++i) {
			B[i] = G->mul_gen(bb[i]);
			if (select[i]) 
				B[i] = B[i].add(A);
		//	io->send_pt(&B[i]);
		    B[i] = B[i].mul(a);
			BA[i] = B[i].add(AaInv);
		}

for(int64_t i = 0; i < length; ++i)
			As[i] = A.mul(bb[i]);


		for(int64_t i = 0; i < length; ++i) {
			res[0] = Hash::KDF(B[i], i) ^ b0[i];
			res[1] = Hash::KDF(BA[i], i) ^ b1[i];
			rmessage[i] = Hash::KDF(As[i], i);
			if(select[i])
				rmessage[i] = rmessage[i] ^ res[1];
			else
				rmessage[i] = rmessage[i] ^ res[0];

	//	std::cout<<"selected msg: "<<rmessage[i]<<endl;
		//	io->send_data(res, 2*sizeof(block));
		}

		delete[] bb;
		delete[] B;
		delete[] As;
    delete[] BA;
//AQUI VA EL OT 


 if (message != nullptr) {
    for (uint i = 0; i < message_len; i++) {
      delete[] message[i];
    }
    delete[] message;
    
  }

for (int64_t i = 0; i < message_len; ++i) {

//cout<<"selected msg: "<<rmessage[i]<<endl;

}
  for (uint i = 0; i < garbled_circuitb.e_init_size; i++) {

    init_labels_bob[i + garbled_circuitb.g_init_size] = rmessage[i];
  }
  for (uint cid = 0; cid < clock_cycles; cid++) {
    for (uint i = 0; i < garbled_circuitb.e_input_size; i++) {
      uint indx = garbled_circuitb.e_init_size
          + cid * garbled_circuitb.e_input_size + i;
      
      input_labels_bob[cid * garbled_circuitb.get_secret_input_size() + i
          + garbled_circuitb.g_input_size] = rmessage[indx];
        

    }
  }


delete[] select;
  delete[] rmessage;
  delete[] b0;
  delete[] b1;

auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    
  //  printf("Result: %.20f\n", sum);
    
    printf("Time measured OT: %.3f mseconds.\n", elapsed.count() * 1e-3);

DUMP("r_key") << R << endl;
  DUMP("r_key") << global_key << endl;

  BlockPair *wires = nullptr;
  CHECK_ALLOC(wires = new BlockPair[garbled_circuit.get_wire_size()]);
  /*
   * The actual value of wire, 0,1 and unknown: -1.
   */
  short *wires_val = nullptr;
  CHECK_ALLOC(wires_val = new short[garbled_circuit.get_wire_size()]);
  for (uint64_t i = 0; i < garbled_circuit.get_wire_size(); i++) {
    wires_val[i] = SECRET;  // All wires are initialed with secret.
  }

  BlockPair *dff_latch = nullptr;
  CHECK_ALLOC(dff_latch = new BlockPair[garbled_circuit.dff_size]);
  short *dff_latch_val = nullptr;
  CHECK_ALLOC(dff_latch_val = new short[garbled_circuit.dff_size]);
  for (uint64_t i = 0; i < garbled_circuit.dff_size; i++) {
    dff_latch_val[i] = SECRET;  // All wires are initialed with secret.
  }

  int *fanout = nullptr;
  CHECK_ALLOC(fanout = new int[garbled_circuit.gate_size]);

  uint64_t num_of_non_xor = NumOfNonXor(garbled_circuit);
  uint64_t garbled_tables_size = num_of_non_xor;
  GarbledTable* garbled_tables_temp = nullptr;
  CHECK_ALLOC(garbled_tables_temp = new GarbledTable[garbled_tables_size]);
  GarbledTable* garbled_tables = nullptr;
  CHECK_ALLOC(garbled_tables = new GarbledTable[garbled_tables_size]);

  uint64_t num_skipped_non_xor_gates = 0;

  uint64_t comm_time = 0;
  uint64_t garble_time = 0;

  AES_KEY AES_Key;
  AES_set_encrypt_key(*global_key, &AES_Key);

  for (uint64_t cid = 0; cid < (clock_cycles); cid++) {
    uint64_t garble_start_time = RDTSC;
    // init
    uint64_t dff_bias = garbled_circuit.get_dff_lo_index();
    int64_t gate_bias = (int64_t) garbled_circuit.get_gate_lo_index();
    if (cid == 0) {
      for (uint64_t i = 0; i < garbled_circuit.dff_size; i++) {
        int64_t wire_index = garbled_circuit.I[i];
        if (wire_index == CONST_ZERO) {
          wires_val[dff_bias + i] = 0;
        } else if (wire_index == CONST_ONE) {
          wires_val[dff_bias + i] = 1;
        } else if (wire_index >= 0
            && wire_index < (int64_t) garbled_circuit.get_init_size()) {
          if (wire_index < (int64_t) garbled_circuit.get_p_init_hi_index()) {
            wires_val[dff_bias + i] = BN_is_bit_set(
                p_init,
                wire_index - (int64_t) garbled_circuit.get_p_init_lo_index());
          } else {
            int64_t label_index = wire_index
                - (int64_t) garbled_circuit.get_p_init_hi_index();

            wires[dff_bias + i].label0 = init_labels[label_index * 2 + 0];
            wires[dff_bias + i].label1 = init_labels[label_index * 2 + 1];
            wires_val[dff_bias + i] = SECRET;
          }
        } else {
      std::cout << "Invalid I: " << wire_index << endl;
          wires_val[dff_bias + i] = 0;  // Wire with invalid I values become 0.
        }
        DUMP("dff") << wires[dff_bias + i].label0 << endl;
      }
    } else {  //copy latched labels
      for (uint64_t i = 0; i < garbled_circuit.dff_size; i++) {
        int64_t wire_index = garbled_circuit.D[i];
        if (wire_index == CONST_ZERO) {
          dff_latch_val[i] = 0;
        } else if (wire_index == CONST_ONE) {
          dff_latch_val[i] = 1;
        } else if (wire_index >= 0
            && wire_index < (int64_t) garbled_circuit.get_wire_size()) {
          dff_latch[i].label0 = wires[wire_index].label0;
          dff_latch[i].label1 = wires[wire_index].label1;
          dff_latch_val[i] = wires_val[wire_index];
        } else {
          std::cout << "Invalid D: " << wire_index << endl;
          dff_latch_val[i] = 0;  // Wire with invalid D values become 0.
        }
      }
      for (uint64_t i = 0; i < garbled_circuit.dff_size; i++) {
        wires[dff_bias + i].label0 = dff_latch[i].label0;
        wires[dff_bias + i].label1 = dff_latch[i].label1;
        wires_val[dff_bias + i] = dff_latch_val[i];
      }
    }

  
    // inputs
    uint64_t p_input_bias = garbled_circuit.get_p_input_lo_index();
    for (uint64_t i = 0; i < garbled_circuit.p_input_size; i++) {
      wires_val[p_input_bias + i] = BN_is_bit_set(
          p_input, cid * garbled_circuit.p_input_size + i);
    }
    uint64_t input_bias = garbled_circuit.get_g_input_lo_index();
    for (uint64_t i = 0; i < garbled_circuit.get_secret_input_size(); i++) {
      wires[input_bias + i].label0 = input_labels[(cid
          * garbled_circuit.get_secret_input_size() + i) * 2 + 0];
      wires[input_bias + i].label1 = input_labels[(cid
          * garbled_circuit.get_secret_input_size() + i) * 2 + 1];
      DUMP("input")
          << input_labels[(cid * garbled_circuit.get_secret_input_size() + i)
              * 2 + 0] << endl;
    }

    for (uint64_t i = 0; i < garbled_circuit.gate_size; i++) {  //known value
      fanout[i] = garbled_circuit.garbledGates[i].fanout;  // init fanout

      GarbledGate& garbledGate = garbled_circuit.garbledGates[i];
      int64_t input0 = garbledGate.input0;
      int64_t input1 = garbledGate.input1;
      int64_t output = garbledGate.output;
      int type = garbledGate.type;

      short input0_value = SECRET;
      if (input0 == CONST_ZERO) {
        input0_value = 0;
      } else if (input0 == CONST_ONE) {
        input0_value = 1;
      } else if (input0 >= 0
          && input0 < (int64_t) garbled_circuit.get_wire_size()) {
        input0_value = wires_val[input0];
      } else {
       std::cout << "Invalid input0 index: " << input0 << endl;
        input0_value = 0;
      }

      short input1_value = SECRET;
      if (input1 == CONST_ZERO) {
        input1_value = 0;
      } else if (input1 == CONST_ONE) {
        input1_value = 1;
      } else if (input1 >= 0
          && input1 < (int64_t) garbled_circuit.get_wire_size()) {
        input1_value = wires_val[input1];
      } else if (type != NOTGATE) {
       std::cout << "Invalid input1 index: " << input1 << endl;
        input1_value = 0;
      }

      GarbleEvalGateKnownValue(input0_value, input1_value, type,
                               &wires_val[output]);

      if (!IsSecret(wires_val[output])) {
        fanout[i] = 0;
        if (IsSecret(input0_value)) {
          ReduceFanout(garbled_circuit, fanout, input0, gate_bias);
        }
        if (IsSecret(input1_value)) {
          ReduceFanout(garbled_circuit, fanout, input1, gate_bias);
        }
      }
    }

    uint64_t garbled_table_ind_temp = 0;

    for (uint64_t i = 0; i < garbled_circuit.gate_size; i++) {  //secret value
      GarbledGate& garbledGate = garbled_circuit.garbledGates[i];
      int64_t input0 = garbledGate.input0;
      int64_t input1 = garbledGate.input1;
      int64_t output = garbledGate.output;
      int type = garbledGate.type;

      if (fanout[i] > 0 && IsSecret(wires_val[output])) {
        BlockPair input0_labels = { zero_block, zero_block };
        short input0_value = SECRET;
        if (input0 == CONST_ZERO) {
          input0_value = 0;
        } else if (input0 == CONST_ONE) {
          input0_value = 1;
        } else if (input0 >= 0
            && input0 < (int64_t) garbled_circuit.get_wire_size()) {
          input0_labels = wires[input0];
          input0_value = wires_val[input0];
        } else {
           std::cout << "Invalid input0 index: " << input0 << endl;
          input0_value = 0;
        }

        BlockPair input1_labels = { zero_block, zero_block };
        short input1_value = SECRET;
        if (input1 == CONST_ZERO) {
          input1_value = 0;
        } else if (input1 == CONST_ONE) {
          input1_value = 1;
        } else if (input1 >= 0
            && input1 < (int64_t) garbled_circuit.get_wire_size()) {
          input1_labels = wires[input1];
          input1_value = wires_val[input1];
        } else if (type != NOTGATE) {
      std::cout << "Invalid input1 index: " << input1 << endl;
          input1_value = 0;
        }

        GarbleGate(input0_labels, input0_value, input1_labels, input1_value,
                   type, cid, i, garbled_tables_temp, &garbled_table_ind_temp,
                   R, AES_Key, &wires[output], &wires_val[output]);
        if (!IsSecret(wires_val[output])) {
          fanout[i] = 0;
          if (IsSecret(input0_value)) {
            ReduceFanout(garbled_circuit, fanout, input0, gate_bias);
          }
          if (IsSecret(input1_value)) {
            ReduceFanout(garbled_circuit, fanout, input1, gate_bias);
          }
        }
      }
    }

   //uint64_t garbled_table_ind = 0;  // fill from 0

    // table select
    for (uint64_t i = 0; i < garbled_table_ind_temp; i++) {
      GarbledTable &table = garbled_tables_temp[i];
      if (fanout[table.gid] > 0) {
        garbled_tables[garbled_table_ind++] = table;
        DUMP("table") << table.row[0] << endl;
        DUMP("table") << table.row[1] << endl;
      }
    }

    for (uint64_t i = 0; i < garbled_circuit.output_size; i++) {
      output_labels[(cid * garbled_circuit.output_size + i) * 2 + 0] =
          wires[garbled_circuit.outputs[i]].label0;
      output_labels[(cid * garbled_circuit.output_size + i) * 2 + 1] =
          wires[garbled_circuit.outputs[i]].label1;
      output_vals[cid * garbled_circuit.output_size + i] =
          wires_val[garbled_circuit.outputs[i]];
      DUMP("output") << wires[garbled_circuit.outputs[i]].label0 << endl;
    }
    garble_time += RDTSC - garble_start_time;

    uint64_t comm_start_time = RDTSC;
   // {
    // io->send_data(&garbled_table_ind, sizeof(uint64_t)); 
     
    //     io->send_data(garbled_tables, garbled_table_ind * sizeof(GarbledTable));

   // }
    // std::cout<<"aLICE SENT: "<<garbled_table_ind<<endl;

comm_time += RDTSC - comm_start_time;

num_skipped_non_xor_gates += num_of_non_xor - garbled_table_ind;
 //if (terminate_period != 0 && garbled_circuit.terminate_id > 0) {
    //  if (cid % terminate_period == 0) {
      //  bool is_terminate = false;
      //  CHECK(
        //    GarbleTransferTerminate(garbled_circuit,
         //                           wires[garbled_circuit.terminate_id],
         //                           wires_val[garbled_circuit.terminate_id],
          //                          &is_terminate, io));

 //if (wires_val[garbled_circuit.terminate_id] == 0) {
 //   (is_terminate) = false;
 // } else if (wires_val[garbled_circuit.terminate_id] == 1) {
  //  (is_terminate) = true;
 // } else {
  //  short terminate_type = get_LSB(wires[garbled_circuit.terminate_id].label0);
    //CHECK(SendData(connfd, &terminate_type, sizeof(short)));
   // io->send_data(&terminate_type, sizeof(short));
  //  short eval_terminate_type;
    //CHECK(RecvData(connfd, &eval_terminate_type, sizeof(short)));
   // io->recv_data(&eval_terminate_type, sizeof(short));

  //  (is_terminate) = (terminate_type == eval_terminate_type);
 // }

      //  if (is_terminate) {
           std::cout << "Alice Terminated in " << cid + 1 << "cc out of "
              << clock_cycles << "cc." << endl;
          clock_cycles = cid + 1;
       //   break;
      //  }
       std::cout << "Non-secret skipped non-XOR gates = "
      << num_skipped_non_xor_gates << " out of "
      << num_of_non_xor * (clock_cycles) << "\t ("
      << (100.0 * num_skipped_non_xor_gates)
          / (num_of_non_xor * (clock_cycles)) << "%)" << endl;

   std::cout << "Total garbled non-XOR gates = "
     << num_of_non_xor * (clock_cycles) - num_skipped_non_xor_gates << endl;

    std::cout << "Alice communication time (cc) = " << comm_time << endl;
   std::cout << "Alice garbling time (cc) = " << garble_time << endl;
      //last clock cycle, not terminated
     // if (cid == (clock_cycles) - 1) {
      //    std::cout
       //     << "Alice Not enough clock cycles. Circuit is not terminated in "
       //     << clock_cycles << "cc." << endl;
     // }
   // }
  }

 block *wires_bob = nullptr;
  CHECK_ALLOC(wires_bob = new block[garbled_circuitb.get_wire_size()]);

  short *wires_valb = nullptr;
  CHECK_ALLOC(wires_valb = new short[garbled_circuitb.get_wire_size()]);
  for (uint64_t i = 0; i < garbled_circuitb.get_wire_size(); i++) {
    wires_valb[i] = SECRET;  // All wires are initialed with unknown.
  }

  block *dff_latchb = nullptr;
  CHECK_ALLOC(dff_latchb = new block[garbled_circuitb.dff_size]);

  short *dff_latch_valb = nullptr;
  CHECK_ALLOC(dff_latch_valb = new short[garbled_circuitb.get_wire_size()]);
  for (uint64_t i = 0; i < garbled_circuitb.get_wire_size(); i++) {
    dff_latch_valb[i] = SECRET;  // All wires are initialed with unknown.

  }

  int *fanoutb = nullptr;
  CHECK_ALLOC(fanoutb = new int[garbled_circuitb.gate_size]);
  

  uint64_t num_of_non_xorb = NumOfNonXor(garbled_circuitb);
 
  GarbledTable* garbled_tablesb = nullptr;
  CHECK_ALLOC(garbled_tablesb = new GarbledTable[num_of_non_xorb]);

  uint64_t comm_timeb = 0;
  uint64_t eval_time = 0;

 AES_KEY AES_Keyb;
  AES_set_encrypt_key(*global_key, &AES_Keyb);
  

  for (uint64_t cid = 0; cid < (clock_cycles); cid++) {
    uint64_t garbled_table_ind_rcv = garbled_table_ind;  // #of tables received from garbler
       //  std::cout<<"BOB got: "<<garbled_table_ind_rcv<<endl;

    uint64_t garbled_table_indb = 0;
garbled_tablesb=garbled_tables;
    uint64_t comm_start_timeb = RDTSC;
   // {
   //          io->recv_data(&garbled_table_ind_rcv, sizeof(uint64_t));
   //           io->recv_data(garbled_tables, garbled_table_ind_rcv * sizeof(GarbledTable));
   // }

    comm_timeb += RDTSC - comm_start_timeb;

    uint64_t eval_start_timeb = RDTSC;
    // init
    uint64_t dff_biasb = garbled_circuitb.get_dff_lo_index();
    int64_t gate_biasb = (int64_t) garbled_circuitb.get_gate_lo_index();
    if (cid == 0) {
      for (uint64_t i = 0; i < garbled_circuitb.dff_size; i++) {
        int64_t wire_indexb = garbled_circuitb.I[i];
        if (wire_indexb == CONST_ZERO) {
          wires_valb[dff_biasb + i] = 0;
        } else if (wire_indexb == CONST_ONE) {
          wires_valb[dff_biasb + i] = 1;
        } else if (wire_indexb >= 0
            && wire_indexb < (int64_t) garbled_circuitb.get_init_size()) {

          if (wire_indexb < (int64_t) garbled_circuitb.get_p_init_hi_index()) {
            wires_valb[dff_biasb + i] = BN_is_bit_set(
                p_init_bob,
                wire_indexb - (int64_t) garbled_circuitb.get_p_init_lo_index());
          } else {
            int64_t label_indexb = wire_indexb
                - (int64_t) garbled_circuitb.get_p_init_hi_index();

            wires_bob[dff_biasb + i] = init_labels_bob[label_indexb];
            wires_valb[dff_biasb + i] = SECRET;
          }
        } else {
          std::cout << "Invalid I: " << wire_indexb << endl;
          wires_valb[dff_biasb + i] = 0;
        }
        DUMP("dff") << wires_bob[dff_biasb + i] << endl;
      }
    } else {  //copy latched labels
      for (uint64_t i = 0; i < garbled_circuitb.dff_size; i++) {
        int64_t wire_indexb = garbled_circuitb.D[i];
        if (wire_indexb == CONST_ZERO) {
          dff_latch_valb[i] = 0;
        } else if (wire_indexb == CONST_ONE) {
          dff_latch_valb[i] = 1;
        } else if (wire_indexb >= 0
            && wire_indexb < (int64_t) garbled_circuitb.get_wire_size()) {
          dff_latchb[i] = wires_bob[wire_indexb];
          dff_latch_valb[i] = wires_valb[wire_indexb];
        } else {
          std::cout << "Invalid D: " << wire_indexb << endl;
          dff_latch_valb[i] = 0;
        }
      }
      for (uint64_t i = 0; i < garbled_circuitb.dff_size; i++) {
        wires_bob[dff_biasb + i] = dff_latchb[i];
        wires_valb[dff_biasb + i] = dff_latch_valb[i];
      }
    }
    // inputs
    uint64_t p_input_biasb = garbled_circuitb.get_p_input_lo_index();
    for (uint64_t i = 0; i < garbled_circuitb.p_input_size; i++) {
      wires_valb[p_input_biasb + i] = BN_is_bit_set(
          p_input_bob, cid * garbled_circuitb.p_input_size + i);
    }

    uint64_t input_biasb = garbled_circuitb.get_g_input_lo_index();
    for (uint64_t i = 0; i < garbled_circuitb.get_secret_input_size(); i++) {
      wires_bob[input_biasb + i] = input_labels_bob[cid
          * garbled_circuitb.get_secret_input_size() + i];
      DUMP("input")
          << input_labels_bob[cid * garbled_circuitb.get_secret_input_size() + i]
          << endl;
    }

    for (uint64_t i = 0; i < garbled_circuitb.gate_size; i++) {  // known values
      fanoutb[i] = garbled_circuitb.garbledGates[i].fanout;  // init fanout

      GarbledGate& garbledGateb = garbled_circuitb.garbledGates[i];
      int64_t input0b = garbledGateb.input0;
      int64_t input1b = garbledGateb.input1;
      int64_t outputb = garbledGateb.output;
      int typeb = garbledGateb.type;

      short input0_valueb = SECRET;
      if (input0b == CONST_ZERO) {
        input0_valueb = 0;
      } else if (input0b == CONST_ONE) {
        input0_valueb = 1;
      } else if (input0b >= 0
          && input0b< (int64_t) garbled_circuitb.get_wire_size()) {
        input0_valueb = wires_valb[input0b];
      } else {
        std::cout << "Invalid input0 index: " << input0b<< endl;
        input0_valueb = 0;
      }

      short input1_valueb = SECRET;
      if (input1b == CONST_ZERO) {
        input1_valueb = 0;
      } else if (input1b == CONST_ONE) {
        input1_valueb = 1;
      } else if (input1b >= 0
          && input1b < (int64_t) garbled_circuitb.get_wire_size()) {
        input1_valueb = wires_val[input1b];
      } else if (typeb != NOTGATE) {
        std::cout << "Invalid input1 index: " << input1b << endl;
        input1_valueb = 0;
      }

      GarbleEvalGateKnownValue(input0_valueb, input1_valueb, typeb,
                               &wires_val[outputb]);
      if (!IsSecret(wires_val[outputb])) {
        fanoutb[i] = 0;
        if (IsSecret(input0_valueb)) {
          ReduceFanout(garbled_circuitb, fanoutb, input0b, gate_biasb);
        }
        if (IsSecret(input1_valueb)) {
          ReduceFanout(garbled_circuitb, fanoutb, input1b, gate_biasb);
        }
      }
    }

    for (uint64_t i = 0; i < garbled_circuitb.gate_size; i++) {  // secret values
      GarbledGate& garbledGate = garbled_circuitb.garbledGates[i];
      int64_t input0 = garbledGate.input0;
      int64_t input1 = garbledGate.input1;
      int64_t output = garbledGate.output;
      int type = garbledGate.type;

      if (fanoutb[i] > 0 && IsSecret(wires_valb[output])) {
        block input0_labels = zero_block;
        short input0_value = SECRET;
        if (input0 == CONST_ZERO) {
          input0_value = 0;
        } else if (input0 == CONST_ONE) {
          input0_value = 1;
        } else if (input0 >= 0
            && input0 < (int64_t) garbled_circuitb.get_wire_size()) {
          input0_labels = wires_bob[input0];
          input0_value = wires_valb[input0];
        } else {
          std::cout << "Invalid input0 index: " << input0 << endl;
          input0_value = 0;
        }

        block input1_labels = zero_block;
        short input1_value = SECRET;
        if (input1 == CONST_ZERO) {
          input1_value = 0;
        } else if (input1 == CONST_ONE) {
          input1_value = 1;
        } else if (input1 >= 0
            && input1 < (int64_t) garbled_circuitb.get_wire_size()) {
          input1_labels = wires_bob[input1];
          input1_value = wires_valb[input1];
        } else if (type != NOTGATE) {
          std::cout << "Invalid input1 index: " << input1 << endl;
          input1_value = 0;
        }

        EvalGate(input0_labels, input0_value, input1_labels, input1_value, type,
                 cid, i, garbled_tablesb, &garbled_table_indb, AES_Keyb,
                 &wires_bob[output], &wires_valb[output]);
        if (!IsSecret(wires_valb[output])) {
          fanoutb[i] = 0;
          if (IsSecret(input0_value)) {
            ReduceFanout(garbled_circuitb, fanoutb, input0, gate_biasb);
          }
          if (IsSecret(input1_value)) {
            ReduceFanout(garbled_circuitb, fanoutb, input1, gate_biasb);
          }
        }
      }
    }

    for (uint64_t i = 0; i < garbled_circuitb.output_size; i++) {
      output_labels_bob[cid * garbled_circuitb.output_size + i] =
          wires_bob[garbled_circuitb.outputs[i]];
      output_vals_bob[cid * garbled_circuitb.output_size + i] =
          wires_valb[garbled_circuitb.outputs[i]];
      DUMP("output") << output_labels_bob[cid * garbled_circuitb.output_size + i]
          << endl;
    }
    eval_time += RDTSC - eval_start_timeb;
    CHECK_EXPR_MSG(garbled_table_indb == garbled_table_ind_rcv,
                   "Number of garbled tables generated "
                   "by Alice and received by Bob are not equal.");

    for (uint64_t j = 0; j < garbled_table_indb; j++) {  // clear tables
      garbled_tablesb[j].gid = (uint32_t)(-1);
    }

   // if (terminate_period != 0 && garbled_circuit.terminate_id > 0) {
    //  if (cid % terminate_period == 0) {
      //  bool is_terminate = false;
      //  CHECK(
       //     EvaluateTransferTerminate(garbled_circuit,
        //                              wires[garbled_circuit.terminate_id],
        //                              wires_val[garbled_circuit.terminate_id],
         //                             &is_terminate, io));
//
      //  if (is_terminate) {
          cout << "Bob Terminated in " << cid + 1 << "cc out of "
             << clock_cycles << "cc." << endl;
         clock_cycles = cid + 1;
        //  break;
      //  }
    //  }
      ///last clock cycle, not terminated
     // if (cid == (*clock_cycles) - 1) {
    //    LOG(ERROR)
     //       << "Bob Not enough clock cycles. Circuit is not terminated in "
     //       << *clock_cycles << "cc." << endl;
    //  }
   // }
  
   std::cout << "Bob communication time (cc) = " << comm_timeb << endl;
 std::cout << "Bob evaluation time (cc) = " << eval_time << endl;
  }

 BIGNUM* output_mask_bn = BN_new();
  BN_hex2bn(&output_mask_bn, output_mask.c_str());


  for (uint64_t cid = 0; cid < clock_cycles; cid++) {
    for (uint64_t i = 0; i < garbled_circuit.output_size; i++) {
      if (output_vals[cid * garbled_circuit.output_size + i] == 0) {
        BN_clear_bit(output_bn, cid * garbled_circuit.output_size + i);
      } else if (output_vals[cid * garbled_circuit.output_size + i] == 1) {
        if (i < (uint64_t) BN_num_bits(output_mask_bn)
            && BN_is_bit_set(output_mask_bn, i) == 1) {
          BN_set_bit(output_bn, cid * garbled_circuit.output_size + i);
        }
      } else {
        short garble_output_type = get_LSB(
            output_labels[(cid * garbled_circuit.output_size + i) * 2 + 0]);
       short eval_output_type = get_LSB(
            output_labels_bob[cid * garbled_circuitb.output_size + i]);
        if (i >= (uint64_t) BN_num_bits(output_mask_bn)
            || BN_is_bit_set(output_mask_bn, i) == 0) {
        // io->send_data(&garble_output_type,sizeof(short));
          BN_clear_bit(output_bn, cid * garbled_circuit.output_size + i);
        } else {
                  // io->recv_data(&eval_output_type,sizeof(short));
          if (eval_output_type != garble_output_type) {
            BN_set_bit(output_bn, cid * garbled_circuit.output_size + i);
          } else {
            BN_clear_bit(output_bn, cid * garbled_circuit.output_size + i);
          }
        }
      }
    }
  }

 // BN_free(output_mask_bn);
  BN_free(output_mask_bn);

 BIGNUM* output_mask_bnb = BN_new();
  BN_hex2bn(&output_mask_bnb, output_mask.c_str());

  for (uint64_t cid = 0; cid < clock_cycles; cid++) {
    for (uint64_t i = 0; i < garbled_circuitb.output_size; i++) {
      if (output_vals_bob[cid * garbled_circuitb.output_size + i] == 0) {
        BN_clear_bit(output_bn_bob, cid * garbled_circuitb.output_size + i);
      } else if (output_vals_bob[cid * garbled_circuitb.output_size + i] == 1) {
        if (i >= (uint64_t) BN_num_bits(output_mask_bnb)
            && BN_is_bit_set(output_mask_bnb, i) == 0) {
          BN_set_bit(output_bn_bob, cid * garbled_circuitb.output_size + i);
        }
      } else {
short garble_output_type = get_LSB(
            output_labels[(cid * garbled_circuit.output_size + i) * 2 + 0]);
                    short eval_output_type = get_LSB(
            output_labels_bob[cid * garbled_circuitb.output_size + i]);
        if (i >= (uint64_t) BN_num_bits(output_mask_bnb)
            || BN_is_bit_set(output_mask_bnb, i) == 0) {
                // io->recv_data(&garble_output_type,sizeof(short));

          if (eval_output_type != garble_output_type) {
            BN_set_bit(output_bn_bob, cid * garbled_circuitb.output_size + i);
          } else {
            BN_clear_bit(output_bn_bob, cid * garbled_circuitb.output_size + i);
          }
        } else {
                  //io->send_data(&eval_output_type,sizeof(short));

          BN_clear_bit(output_bn_bob, cid * garbled_circuitb.output_size + i);
        }
      }
    }
  }

  BN_free(output_mask_bnb);




delete[] init_labels;
  delete[] input_labels;
  delete[] output_labels;
  delete[] output_vals;
  delete[] init_labels_bob;
  delete[] input_labels_bob;
  delete[] output_labels_bob;
  delete[] output_vals_bob;


CHECK(  
       OutputBN2StrHighMem(garbled_circuit, output_bn, clock_cycles,
                           output_mode, output_str));
//std::cout<<"outputbn "<<output_bn<<endl;
//std::cout<<"outputbn bob "<<*output_bn_bob<<endl;

CHECK(  
       OutputBN2StrHighMem(garbled_circuitb, output_bn_bob, clock_cycles,
                           output_mode, output_str_bob));



  BN_free(p_init);
  BN_free(p_init_bob);
  BN_free(p_input);
  BN_free(p_input_bob);
  BN_free(g_init);
  BN_free(g_input);
  BN_free(output_bn);
  BN_free(e_init);
  BN_free(e_input);
  RemoveGarbledCircuit(&garbled_circuit);
  RemoveGarbledCircuit(&garbled_circuitb);

  return SUCCESS;
}
  
              
/*
int EvaluateStr(const string& scd_file_address, const string& p_init_str,
                const string& p_input_str, const string& init_str,
                const string& input_str, uint64_t clock_cycles,
                const string& output_mask, int64_t terminate_period,
                OutputMode output_mode, bool disable_OT, bool low_mem_foot,
                string* output_str) {
  if (clock_cycles == 0) {
    return FAILURE;
  }

  GarbledCircuit garbled_circuit;
  if (ReadSCD(scd_file_address, &garbled_circuit) == FAILURE) {
    std::cout  << "Error while reading scd file: " << scd_file_address << endl;
    return FAILURE;
  }
  FillFanout(&garbled_circuit);

  if (terminate_period != 0 && garbled_circuit.terminate_id == 0) {
    std::cout  << "There is no terminate signal in the circuit."
               " The terminate period should be 0."
               << endl;
    return FAILURE;
  }

  // allocate init and input values and translate form string
  BIGNUM* p_init = BN_new();
  BIGNUM* p_input = BN_new();
  BIGNUM* e_init = BN_new();
  BIGNUM* e_input = BN_new();
  BIGNUM* output_bn = BN_new();
  CHECK(
      ParseInitInputStr(init_str, input_str, garbled_circuit.e_init_size,
                        garbled_circuit.e_input_size, clock_cycles, &e_init,
                        &e_input));
  CHECK(
      ParseInitInputStr(p_init_str, p_input_str, garbled_circuit.p_init_size,
                        garbled_circuit.p_input_size, clock_cycles, &p_init,
                        &p_input));
   
  // global key
  PRG pg;
  block* global_key = new block[sizeof(block)];
     pg.random_block(global_key,sizeof(block));

   	//io->sync();


      //    io->flush();   

 


    /*CHECK(
        EvaluateBNHighMem(garbled_circuit, p_init, p_input, e_init, e_input,
                          &clock_cycles, output_mask, terminate_period,
                          output_mode, output_bn, global_key, disable_OT,
                          io,ferretcot));
    CHECK(
        OutputBN2StrHighMem(garbled_circuit, output_bn, clock_cycles,
                            output_mode, output_str));
  
  
  BN_free(p_init);
  BN_free(p_input);
  BN_free(e_init);
  BN_free(e_input);
  BN_free(output_bn);

  RemoveGarbledCircuit(&garbled_circuit);
  return SUCCESS;
}

*/