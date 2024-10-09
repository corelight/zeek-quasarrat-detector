module QuasarRAT;

export {
	## The notices when QuasarRAT C2 is observed.
	redef enum Notice::Type += { C2_Traffic_Observed_Cert };
}

event ssl_established(c: connection)
	{
	if ( ! c?$ssl )
		return;

	if ( c$ssl?$subject && c$ssl$subject == "CN=Quasar Server CA" )
		NOTICE([ $note=QuasarRAT::C2_Traffic_Observed_Cert, $msg="Potential QuasarRAT C2 - default SSL certificate discovered.",
		    $conn=c, $identifier=cat(c$id$orig_h, c$id$resp_h) ]);
	}
