use sections::*;
use std::net::{SocketAddr, UdpSocket};

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
                let query = handle_recv(&buf, size, source);

                handle_send(&mut response, query);

                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
        }
    }
}

fn handle_recv(in_buf: &[u8], size: usize, source: SocketAddr) -> Query<'_> {
    println!("Received {} bytes from {}", size, source);
    Query::parse(in_buf).1
}

fn handle_send(res_buf: &mut [u8], query: Query<'_>) {
    let (mut res_buf, mut header) = handle_header(&query.header, res_buf);
    header.set_question_count(query.questions.len() as _);

    for question in query.questions {
        res_buf = question.write(res_buf);
    }
}

fn handle_header<'a>(
    header: &DNSHeader<&[u8]>,
    res_buf: &'a mut [u8],
) -> (&'a mut [u8], DNSHeader<&'a mut [u8]>) {
    let (h, buf) = res_buf.split_at_mut(12);
    let mut new_header = DNSHeader(h);
    new_header.set_packet_id(header.packet_id());
    new_header.set_query_reponse_indicator(true);
    new_header.set_operation_code(0);
    new_header.set_auth_answer(false);
    new_header.set_truncation(false);
    new_header.set_recursion_desired(false);
    new_header.set_response_code(0);
    new_header.set_question_count(header.question_count());
    new_header.set_answer_record_count(0);
    new_header.set_auth_record_count(0);
    new_header.set_additional_record_count(0);

    (buf, new_header)
}

mod sections {
    use num_enum::TryFromPrimitive;

    pub trait Parse<'b> {
        fn parse<'bin>(in_buf: &'bin [u8]) -> (&'bin [u8], Self)
        where
            'bin: 'b;
    }

    pub trait Write {
        fn write<'bout>(&self, buf: &'bout mut [u8]) -> &'bout mut [u8];
    }

    #[derive(Debug)]
    pub struct Query<'in_buffer> {
        pub header: DNSHeader<&'in_buffer [u8]>,
        pub questions: Vec<Question<'in_buffer>>,
    }

    impl<'f> Parse<'f> for Query<'f> {
        fn parse<'bin>(in_buf: &'bin [u8]) -> (&'bin [u8], Self)
        where
            'bin: 'f,
        {
            let (mut in_buf, header) = DNSHeader::parse(in_buf);
            let mut questions = vec![];
            for _ in 0..header.question_count() {
                let (buf, question) = Question::parse(in_buf);
                in_buf = buf;
                questions.push(question);
            }
            (in_buf, Self { header, questions })
        }
    }

    #[derive(Debug)]
    pub struct Question<'in_buf> {
        pub labels: Labels<'in_buf>,
        pub qtype: QuestionTypes,
        pub qclass: QuestionClasses,
    }

    impl<'f> Parse<'f> for Question<'f> {
        fn parse<'bin>(in_buf: &'bin [u8]) -> (&'bin [u8], Self)
        where
            'bin: 'f,
        {
            let (in_buf, labels) = Labels::parse(in_buf);
            let (in_buf, qtype) = QuestionTypes::parse(in_buf);
            let (in_buf, qclass) = QuestionClasses::parse(in_buf);

            (
                in_buf,
                Question {
                    labels,
                    qtype,
                    qclass,
                },
            )
        }
    }

    impl Write for Question<'_> {
        fn write<'bout>(&self, mut buf: &'bout mut [u8]) -> &'bout mut [u8] {
            buf = self.labels.write(buf);

            buf[0..2].copy_from_slice(&(self.qtype as u16).to_be_bytes());
            buf[2..4].copy_from_slice(&(self.qclass as u16).to_be_bytes());

            &mut buf[4..]
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Labels<'ibuf> {
        words: Vec<Label<'ibuf>>,
    }

    impl<'f> Parse<'f> for Labels<'f> {
        fn parse<'bin>(in_buf: &'bin [u8]) -> (&'bin [u8], Self)
        where
            'bin: 'f,
        {
            let mut buf = in_buf;
            let mut words = Vec::new();
            loop {
                match buf.get(0) {
                    None => panic!(
                        "something when wrong, \
                         while processing the buffer \
                         should not be empty already."
                    ),
                    Some(0x0) => {
                        buf = &buf[1..];
                        break (buf, Self { words });
                    }
                    Some(_) => {
                        let (b, word) = Label::parse(buf);
                        buf = b;
                        words.push(word);
                    }
                }
            }
        }
    }

    impl<'f> Write for Labels<'f> {
        fn write<'bout>(&self, mut buf: &'bout mut [u8]) -> &'bout mut [u8] {
            for lable in &self.words {
                buf = lable.write(buf);
            }

            buf[0] = 0;

            &mut buf[1..]
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Label<'ibuf> {
        word: &'ibuf str,
    }

    impl Write for Label<'_> {
        fn write<'bout>(&self, buf: &'bout mut [u8]) -> &'bout mut [u8] {
            buf[0] = self.word.len() as _;
            buf[1..=self.word.len()].copy_from_slice(self.word.as_bytes());

            &mut buf[1 + self.word.len()..]
        }
    }

    impl<'f> Parse<'f> for Label<'f> {
        fn parse<'bin>(in_buf: &'bin [u8]) -> (&'bin [u8], Self)
        where
            'bin: 'f,
        {
            let offset = (in_buf[0] + 1) as usize;
            let word = &in_buf[1..offset];
            let word = std::str::from_utf8(word).expect("unable to convert domain into utf8");
            (&in_buf[offset..], Label { word })
        }
    }

    fn cast_helper<T>(in_buf: &[u8]) -> (&[u8], T)
    where
        T: TryFromPrimitive<Primitive = u16>,
        <T as TryFromPrimitive>::Error: std::fmt::Debug,
    {
        let res = in_buf[0..2].try_into().expect("unable to convert");

        let res = T::try_from_primitive(u16::from_be_bytes(res))
            .expect("unable to convert to the given type");

        (&in_buf[2..], res)
    }

    #[derive(Debug, Clone, Copy, Eq, PartialEq, TryFromPrimitive)]
    #[repr(u16)]
    pub enum QuestionTypes {
        A = 1,      // a host address
        NS = 2,     // an authoritative name server
        MD = 3,     // a mail destination (Obsolete - use MX)
        MF = 4,     // a mail forwarder (Obsolete - use MX)
        CNAME = 5,  // the canonical name for an alias
        SOA = 6,    // marks the start of a zone of authority
        MB = 7,     // a mailbox domain name (EXPERIMENTAL)
        MG = 8,     // a mail group member (EXPERIMENTAL)
        MR = 9,     // a mail rename domain name (EXPERIMENTAL)
        NULL = 10,  // a null RR (EXPERIMENTAL)
        WKS = 11,   // a well known service description
        PTR = 12,   // a domain name pointer
        HINFO = 13, // host information
        MINFO = 14, // mailbox or mail list information
        MX = 15,    // mail exchange
        TXT = 16,   // text strings
    }

    impl<'f> Parse<'f> for QuestionTypes {
        fn parse<'bin>(in_buf: &'bin [u8]) -> (&'bin [u8], Self)
        where
            'bin: 'f,
        {
            cast_helper(in_buf)
        }
    }

    #[derive(Debug, Clone, Copy, Eq, PartialEq, TryFromPrimitive)]
    #[repr(u16)]
    pub enum QuestionClasses {
        IN = 1, //the Internet
        CS = 2, //the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
        CH = 3, //the CHAOS class
        HS = 4, //Hesiod [Dyer 87]
    }

    impl<'f> Parse<'f> for QuestionClasses {
        fn parse<'bin>(in_buf: &'bin [u8]) -> (&'bin [u8], Self)
        where
            'bin: 'f,
        {
            cast_helper(in_buf)
        }
    }

    bitfield::bitfield! {
        pub struct DNSHeader(MSB0 [u8]);
        impl Debug;
        u8;
        pub u16, packet_id,set_packet_id: 0x0F, 0x00;
        pub query_reponse_indicator, set_query_reponse_indicator: 0x10;
        pub operation_code, set_operation_code: 0x14, 0x11;
        pub auth_answer, set_auth_answer: 0x15;
        pub truncation, set_truncation: 0x16;
        pub recursion_desired, set_recursion_desired: 0x17;
        pub recursion_available, set_recursion_available: 0x18;
        pub reserved_z, set_reserved_z: 0x1B, 0x19;
        pub response_code, set_response_code: 0x1F, 0x1C;
        pub u16, question_count, set_question_count: 0x2F, 0x20;
        pub u16, answer_record_count, set_answer_record_count: 0x3F, 0x30;
        pub u16, auth_record_count, set_auth_record_count: 0x4F, 0x4F;
        pub u16, additional_record_count, set_additional_record_count: 0x5F, 0x50;
    }

    impl<'f> Parse<'f> for DNSHeader<&'f [u8]> {
        fn parse<'bin>(in_buf: &'bin [u8]) -> (&'bin [u8], Self)
        where
            'bin: 'f,
        {
            let (a, b) = in_buf.split_at(12);

            (b, Self(a))
        }
    }
    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn test_dns_header() {
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

        #[test]
        fn test_lables() {
            let domain = "domain";
            let end = "com";
            let setup = |mut buf: &mut [u8]| {
                buf[0] = domain.len() as _;
                buf[1..=domain.len()].copy_from_slice(domain.as_bytes());
                buf = &mut buf[1 + domain.len()..];

                buf[0] = end.len() as _;
                buf[1..=end.len()].copy_from_slice(end.as_bytes());
                buf = &mut buf[1 + end.len()..];
                buf[0] = 0;

                1 + domain.len() + 1 + end.len() + 1
            };

            let mut h = [0; 12];
            let buf_len = setup(&mut h);

            let (buf, lables) = Labels::parse(&h);
            assert_eq!(lables.words[0].word, domain);
            assert_eq!(lables.words[1].word, end);
            assert_eq!(h.len() - buf.len(), buf_len);
        }

        #[test]
        fn test_questions() {
            let domain = "domain";
            let end = "com";
            let setup = |mut buf: &mut [u8]| {
                buf[0] = domain.len() as _;
                buf[1..=domain.len()].copy_from_slice(domain.as_bytes());
                buf = &mut buf[1 + domain.len()..];

                buf[0] = end.len() as _;
                buf[1..=end.len()].copy_from_slice(end.as_bytes());
                buf = &mut buf[1 + end.len()..];
                buf[0] = 0;
                buf = &mut buf[1..];

                buf[0..2].copy_from_slice(&(QuestionTypes::MX as u16).to_be_bytes());
                buf = &mut buf[2..];

                buf[0..2].copy_from_slice(&(QuestionClasses::CH as u16).to_be_bytes());

                1 + domain.len() + 1 + end.len() + 1 + 2 + 2
            };

            let mut h = [0; 16];
            let buf_len = setup(&mut h);

            let (buf, question) = Question::parse(&h);
            assert_eq!(question.labels.words[0].word, domain);
            assert_eq!(question.labels.words[1].word, end);

            assert_eq!(question.qtype, QuestionTypes::MX);
            assert_eq!(question.qclass, QuestionClasses::CH);
            assert_eq!(h.len() - buf.len(), buf_len);
        }
    }
}
