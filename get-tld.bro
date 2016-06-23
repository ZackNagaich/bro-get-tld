@load base/bif/input.bif.bro
@load base/bif/strings.bif.bro

type Val: record{
	domain: string;
};

global tld_set: set[string];


event tldentry(description: Input::EventDescription, tpe: Input::Event, domain: string){
	if(strstr(domain,"/")==0 && |domain| > 1){
		add tld_set[domain];
	}
}

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
	print get_tld("subdomain.abc.teaches-yoga.com");
}



event bro_init(){
	Input::add_event([$source="public_suffix_list.dat",$reader=Input::READER_RAW,$name="tld_stream",$fields=Val,$want_record=F,$ev=tldentry]);
}


