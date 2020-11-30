simple Traffic {
    parameters:
  // 	 	int type;//0- normal; 1-dDos 2-Flash crowd
  	//	int rate=default(1);
  		double nor_prob=default(0.477);
  		double dos_prob=default(0.142);
      	double flash_prob=default(0.381);
      	int nor_host=default(50);
      	int dos_host=default(15);
      	int flash_host=default(40);
  	gates:
  		output out; 
}

//simple Packet{
//   parameters:
//	//	int class;//0- normal; 1-dDos 2-Flash crowd
//		double prob;
//		int pck_index;
//		
//}



 simple Target{
     parameters: 
       //int grp_index;
       //double score;
       int distance;//group dist
	   double thresh_entropy=default(3);
	   double thresh_score=default(0);
	//   int sys_entropy=default(0);
	  gates:
	     input in;  
    // submodules:
    //	 packet_class: Packet;
    //	 group_class: Group;

 }

network Network {
	submodules:
	    traf: Traffic;
	    target:Target;
	connections:
	    traf.out-->target.in;
	        
	    
}