// Uncomment this block to pass the first stage
use std::net::{SocketAddr, UdpSocket};

use bitfield::bitfield;

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
            Ok((size, source)) => {
                let mut response = [0; 512];
                handle_recv(&buf, &mut response, size, source);

                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
        }
    }
}

fn handle_recv(in_buf: &[u8], res_buf: &mut [u8], size: usize, source: SocketAddr) {
    println!("Received {} bytes from {}", size, source);
    println!("buffer {:x?}", &in_buf[0..12]);

    let _header = DNSHeader(&in_buf[0..12]);

    let mut new_header = DNSHeader(&mut res_buf [0..12]);
    new_header.set_packet_id(1234);
    new_header.set_query_reponse_indicator(true);
    new_header.set_operation_code(0);
    new_header.set_auth_answer(false);
    new_header.set_truncation(false);
    new_header.set_recursion_desired(false);
    new_header.set_response_code(0);
    new_header.set_question_count(0);
    new_header.set_answer_record_count(0);
    new_header.set_auth_record_count(0);
    new_header.set_additional_record_count(0);
}

bitfield! {
    struct DNSHeader(MSB0 [u8]);
    impl Debug;
    u8;
    u16, packet_id,set_packet_id: 0x0F, 0x00;
    query_reponse_indicator, set_query_reponse_indicator: 0x10;
    operation_code, set_operation_code: 0x14, 0x11;
    auth_answer, set_auth_answer: 0x15;
    truncation, set_truncation: 0x16;
    recursion_desired, set_recursion_desired: 0x17;
    recursion_available, set_recursion_available: 0x18;
    reserved_z, set_reserved_z: 0x1B, 0x19;
    response_code, set_response_code: 0x1F, 0x1C;
    u16, question_count, set_question_count: 0x2F, 0x20;
    u16, answer_record_count, set_answer_record_count: 0x3F, 0x30;
    u16, auth_record_count, set_auth_record_count: 0x4F, 0x4F;
    u16, additional_record_count, set_additional_record_count: 0x5F, 0x50;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn dns_header() {
        let h = [
            0x4b, 0x22, 0x1, 0x20, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x1, 0x1,
        ];

        let header = DNSHeader(&h);

        assert_eq!(0x4b22, header.packet_id());
        assert_eq!(false, header.query_reponse_indicator());
        assert_eq!(0, header.operation_code());
        assert_eq!(false, header.auth_answer());
        assert_eq!(false, header.truncation());
        assert_eq!(true, header.recursion_desired());
        assert_eq!(false, header.recursion_available());
        assert_eq!(2, header.reserved_z());
        assert_eq!(0, header.response_code());
        assert_eq!(1, header.question_count());
        assert_eq!(0, header.answer_record_count());
        assert_eq!(1, header.auth_record_count());
        assert_eq!(0x0101, header.additional_record_count());
    }
}
