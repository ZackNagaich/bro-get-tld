@load base/bif/input.bif.bro
@load base/bif/strings.bif.bro

type DomainRecord: record{
	domain: string;
};

global tld_set: set[string];

#event callback utilized by input framework to populate set with domains
event tldentry(description: Input::EventDescription, tpe: Input::Event, domain: string){

	#ignore comments and add domains to index_set
	if(strstr(domain,"/")==0 && |domain| > 1){
		add tld_set[domain];
	}
}

#called when expiration is hit for wrapper_table, set to 3 days
#clears out tld_set, downloads new suffix list from mozilla and re imports into table
function do_expire(data: set[string], index: string):interval {

	#clear out set of old tld's so we can repopulate from new list
	for (e in tld_set){
		delete tld_set[e];
	}

	piped_exec("wget -O public_suffix_list.dat https://publicsuffix.org/list/public_suffix_list.dat","");	
	Input::add_event([$source="public_suffix_list.dat",$reader=Input::READER_RAW,$name="tld_stream",$fields=DomainRecord,$want_record=F,$ev=tldentry]);
	Input::remove("tld_stream");

	return 3day;
}

#table used to wrap our set in, we are doing this so we can set an expire for the entire set of domains
global wrapper_table: table[string] of set[string] &write_expire=3day &expire_func=do_expire;

#takes a domain as a string, strips it to it's tld and checks membership in public suffix list
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

#once we finish populating our set of domains, let's wrap it up in a table so we can apply expiration
event Input::end_of_data(name: string, source: string){
	wrapper_table["set"] = tld_set;
	#print wrapper_table;
}

#on first run, download suffix list and import domains
event bro_init(){
	piped_exec("wget -O public_suffix_list.dat https://publicsuffix.org/list/public_suffix_list.dat","");
	Input::add_event([$source="public_suffix_list.dat",$reader=Input::READER_RAW,$name="tld_stream",$fields=DomainRecord,$want_record=F,$ev=tldentry]);
	Input::remove("tld_stream");
}
