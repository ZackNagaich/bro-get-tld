@load base/bif/input.bif.bro
@load base/bif/strings.bif.bro

type DomainRecord: record{
	domains: set[string];
};

global tld_table: set[string];

event tldentry(description: Input::EventDescription, tpe: Input::Event, domain: string){

	#ignore comments and add domains to index_set
	if(strstr(domain,"/")==0 && |domain| > 1){
		add tld_set[domain];
	}
}

function do_expire(data: set[set[string]], index: set[string]):interval {

	#clear out set of old tld's so we can repopulate from new list
	for (e in tld_set){
		delete tld_set[e];
	}

	piped_exec("wget -O public_suffix_list.dat https://publicsuffix.org/list/public_suffix_list.dat","");	
	Input::add_event([$source="public_suffix_list.dat",$reader=Input::READER_RAW,$name="tld_stream",$fields=DomainRecord,$want_record=F,$ev=tldentry]);

	return 3day;
}

global wrapper_set: set[set[string]] &create_expire=5sec &expire_func=do_expire;

function get_tld(domain: string):any{
	
	local strvec: vector of string;
	strvec = split_string(domain,/\./);
	local tld_domain: string = domain;
	if(|strvec| > 2){
		local newvec: vector of string;
		newvec[1] = strvec[|strvec|-1];
		newvec[0] = strvec[|strvec| -2];
		tld_domain = join_string_vec(newvec,".");
	}

	if(tld_domain in tld_set){
		return tld_domain;
	}
	else{
		return F;
	}
}


event Input::end_of_data(name: string, source: string){
	#we have finished reading the suffix list so let's add the tld_set to the wrapper set
	#this will provide us with a set of a set, which will allow for expiration of all domains at once
	add wrapper_set[tld_set];
}

event bro_init(){
	piped_exec("wget -O public_suffix_list.dat https://publicsuffix.org/list/public_suffix_list.dat","");
	Input::add_event([$source="public_suffix_list.dat",$reader=Input::READER_RAW,$name="tld_stream",$fields=DomainRecord,$want_record=F,$ev=tldentry]);
}
