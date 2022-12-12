var client_messages = 1;
var client_id_str = "-";

function parseCSKVpairs(cskvpairs, key) {
    if ( cskvpairs.length ) {
        var kvpairs = cskvpairs.split(',');
        for ( var i = 0; i < kvpairs.length; i++ ) {
            var kvpair = kvpairs[i].split('=');
            if ( kvpair[0].toUpperCase() == key ) {
                return kvpair[1];
            }
        }
    }
    return ""; // Default condition
}

// PoC function to verify if mqtt username corresponds to the subject name of the supplied SSL certificate
// For production grade a more robust header parsing (remaining length, handling of password header and mqtt control codes without header)
// would have to be implemented. 
function preread_verify(s) {
    var collect = '';

    s.on('upload', async function (data, flags) {
        collect += data;
		
        if (collect.length >= 1 ) {
            s.off('upload');
			
			var protocol = collect.substring(4,8);
			var packet_type_flags_byte = collect.charCodeAt(0);
			var protocol_level_byte = collect.charCodeAt(8);
			var connect_flags_byte = collect.charCodeAt(9);
			
			var username_flag = (connect_flags_byte & 2**7) > 0;
			var password_flag = (connect_flags_byte & 2**6) > 0;
			var will_flag = (connect_flags_byte & 2**2) > 0;
			
			
			s.log(collect);
			s.log("MQTT protocol = " + protocol);
			s.log("MQTT packet type+flags = " + packet_type_flags_byte.toString());
			s.log("MQTT protocol_level = " + protocol_level_byte.toString());
			s.log("MQTT connect_flags = " + connect_flags_byte.toString() + " username = " + username_flag + " password = " + password_flag);
			
			if ( packet_type_flags_byte < 16 || packet_type_flags_byte >= 32 ) {
				s.log("Received unexpected MQTT packet type+flags: " + packet_type_flags_byte.toString());
			} 
			else {
			
				var offset = 12 ;
				var clientId_len =  (((collect.charCodeAt(offset) & 0xFF) << 8) | (collect.charCodeAt(offset+1) & 0xFF)); 
			
				offset = offset + 2 ;
				var client_id = collect.substring(offset,offset+clientId_len);
				s.log("clientID length = " + clientId_len  + " client_id => " + client_id );
				offset = offset + clientId_len + 1 - 1;
				
				var will_topic = ''
				var will_message = ''
				if (will_flag) {
					var will_len = (((collect.charCodeAt(offset) & 0xFF) << 8) | (collect.charCodeAt(offset+1) & 0xFF));
					will_topic = collect.substring(offset+2,offset + 2 + will_len);
					
					offset = offset + 2 + will_len + 1 - 1;
					var will_mes_len = (((collect.charCodeAt(offset) & 0xFF) << 8) | (collect.charCodeAt(offset+1) & 0xFF));
					
					will_message = collect.substring(offset+2,offset + 2 + will_msg_len);
					offset = offset + 2 + will_mes_len + 1 - 1;
				}
				
				var username = "";
				var pw = ""
				if (username_flag) {
					var username_len = (((collect.charCodeAt(offset) & 0xFF) << 8) | (collect.charCodeAt(offset+1) & 0xFF));
					username = collect.substring(offset+2,offset + 2 + username_len);
					s.log("username_len = " + username_len + " username => " + username);
					offset = offset + 2 + username_len + 1 - 1;
					s.log("MQTT username = " + username);
				}
				if (password_flag) {
					var pw_len = (((collect.charCodeAt(offset) & 0xFF) << 8) | (collect.charCodeAt(offset+1) & 0xFF));
					pw = collect.substring(offset+2,offset + 2 + pw_len);
					s.log("password_len = " + pw_len + " pw => " + pw);
					offset = offset + 2 + pw_len + 1 - 1;
					
					s.log("MQTT password = " + pw);
				}
				
				var client_cert_cn = parseCSKVpairs(s.variables.ssl_client_s_dn, "CN");
				s.log("X.509 CN = " + client_cert_cn);
					
				if ( client_cert_cn.length && client_cert_cn != username ) {
					s.log("Client certificate common name (" + client_cert_cn + ") does not match username (" + username +")");
					return s.deny(); // Close the TCP connection (logged as 500)
				}
			}
			s.done();

        } else if (collect.length) {
            s.deny();
        }
		
    });
}



function setClientId(s) {
    return client_id_str;
}

export default {setClientId, preread_verify};
