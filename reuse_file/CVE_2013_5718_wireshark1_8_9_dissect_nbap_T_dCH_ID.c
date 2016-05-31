


static int
dissect_nbap_T_dCH_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 626 "../../asn1/nbap/nbap.cnf"

  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &dch_id, FALSE);
	if(g_num_dch_in_flow>0){
		g_dchs_in_flow_list[g_num_dch_in_flow-1]=dch_id;
		nbap_dch_chnl_info[dch_id].next_dch = 0;
		if(prev_dch_id != 0){
			nbap_dch_chnl_info[prev_dch_id].next_dch = dch_id;
		}
	}



  return offset;
}