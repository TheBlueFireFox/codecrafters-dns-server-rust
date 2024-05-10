use sections::*;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    let mut response = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
            Ok((size, source)) => {
                let query = handle_recv(&buf, size, source);

                let resp = process(query);
                let len = handle_send(&mut response, &resp);
                let res = &response[..len];

                udp_socket
                    .send_to(res, source)
                    .expect("Failed to send response");
            }
        }
    }
}

fn handle_recv(in_buf: &[u8], size: usize, source: SocketAddr) -> Request<'_> {
    println!("Received {} bytes from {}", size, source);
    Request::parse(in_buf).1
}

fn process(req: Request<'_>) -> Response<'_> {
    let mut answers = vec![];

    for question in &req.questions {
        let at = AnswerTypes::A(Ipv4Addr::new(8, 8, 8, 8));
        let rr = ResourceRecord {
            name: question.labels.clone(),
            atype: question.qtype,
            aclass: question.qclass,
            ttl: 60,
            len: at.len(),
            answer: at,
        };

        answers.push(rr);
    }

    let header = handle_header(&req.header, answers.len());

    let answers = Answers { answers };

    Response {
        header,
        questions: req.questions,
        answers,
    }
}

fn handle_send(res_buf: &mut [u8], res: &Response<'_>) -> usize {
    let len = res_buf.len();
    let buf = res.write(res_buf);
    len - buf.len()
}

fn handle_header<'a>(header: &DNSHeader<&[u8]>, anwsers: usize) -> DNSHeader<[u8; 12]> {
    let mut new_header = DNSHeader([0; 12]);
    new_header.set_packet_id(header.packet_id());
    new_header.set_query_reponse_indicator(true);
    new_header.set_operation_code(0);
    new_header.set_auth_answer(false);
    new_header.set_truncation(false);
    new_header.set_recursion_desired(false);
    new_header.set_recursion_available(false);
    new_header.set_reserved_z(0);
    new_header.set_response_code(0);
    new_header.set_question_count(header.question_count());
    new_header.set_answer_record_count(anwsers as _);
    new_header.set_auth_record_count(0);
    new_header.set_additional_record_count(0);

    new_header
}

mod sections {
    use std::net::Ipv4Addr;

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
    pub struct Request<'in_buffer> {
        pub header: DNSHeader<&'in_buffer [u8]>,
        pub questions: Vec<Question<'in_buffer>>,
    }

    impl<'f> Parse<'f> for Request<'f> {
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
    pub struct Response<'in_buffer> {
        pub header: DNSHeader<[u8; 12]>,
        pub questions: Vec<Question<'in_buffer>>,
        pub answers: Answers<'in_buffer>,
    }

    impl Write for Response<'_> {
        fn write<'bout>(&self, mut buf: &'bout mut [u8]) -> &'bout mut [u8] {
            buf = self.header.write(buf);
            for question in &self.questions {
                buf = question.write(buf);
            }

            buf = self.answers.write(buf);
            buf
        }
    }

    #[derive(Debug)]
    pub struct Answers<'in_buf> {
        pub answers: Vec<ResourceRecord<'in_buf>>,
    }

    impl Write for Answers<'_> {
        fn write<'bout>(&self, mut buf: &'bout mut [u8]) -> &'bout mut [u8] {
            for answer in &self.answers {
                buf = answer.write(buf);
            }
            buf
        }
    }

    #[derive(Debug)]
    pub struct ResourceRecord<'in_buf> {
        pub name: Labels<'in_buf>,
        pub atype: QueryTypes,
        pub aclass: QueryClasses,
        pub ttl: u32,
        pub len: u16,
        pub answer: AnswerTypes, // will contain the RDATA as payload
    }

    impl Write for ResourceRecord<'_> {
        fn write<'bout>(&self, mut buf: &'bout mut [u8]) -> &'bout mut [u8] {
            buf = self.name.write(buf);
            buf = self.atype.write(buf);
            buf = self.aclass.write(buf);
            buf = cast_helper_u32(self.ttl, buf);
            buf = cast_helper_u16(self.len, buf);
            buf = self.answer.write(buf);
            buf
        }
    }

    #[derive(Debug)]
    pub struct Question<'in_buf> {
        pub labels: Labels<'in_buf>,
        pub qtype: QueryTypes,
        pub qclass: QueryClasses,
    }

    impl<'f> Parse<'f> for Question<'f> {
        fn parse<'bin>(in_buf: &'bin [u8]) -> (&'bin [u8], Self)
        where
            'bin: 'f,
        {
            let (in_buf, labels) = Labels::parse(in_buf);
            let (in_buf, qtype) = QueryTypes::parse(in_buf);
            let (in_buf, qclass) = QueryClasses::parse(in_buf);

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
            buf = self.qtype.write(buf);
            buf = self.qclass.write(buf);

            buf
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
            let (a, buf) = buf.split_at_mut(1);
            a[0] = self.word.len() as _;
            let (a, buf) = buf.split_at_mut(self.word.len());
            a.copy_from_slice(self.word.as_bytes());

            buf
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

    fn try_from_primitive<T>(in_buf: &[u8]) -> (&[u8], T)
    where
        T: TryFromPrimitive<Primitive = u16>,
        <T as TryFromPrimitive>::Error: std::fmt::Debug,
    {
        let res = in_buf[0..2].try_into().expect("unable to convert");

        let res = T::try_from_primitive(u16::from_be_bytes(res))
            .expect("unable to convert to the given type");

        (&in_buf[2..], res)
    }

    fn cast_helper_u16(v: u16, buf: &mut [u8]) -> &mut [u8] {
        let (s, buf) = buf.split_at_mut(2);
        s.copy_from_slice(&v.to_be_bytes());
        buf
    }

    fn cast_helper_u32(v: u32, buf: &mut [u8]) -> &mut [u8] {
        let (s, buf) = buf.split_at_mut(4);
        s.copy_from_slice(&v.to_be_bytes());
        buf
    }

    #[allow(dead_code)]
    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub enum AnswerTypes {
        A(Ipv4Addr), // a host address
        NS,          // an authoritative name server
        MD,          // a mail destination (Obsolete - use MX)
        MF,          // a mail forwarder (Obsolete - use MX)
        CNAME,       // the canonical name for an alias
        SOA,         // marks the start of a zone of authority
        MB,          // a mailbox domain name (EXPERIMENTAL)
        MG,          // a mail group member (EXPERIMENTAL)
        MR,          // a mail rename domain name (EXPERIMENTAL)
        NULL,        // a null RR (EXPERIMENTAL)
        WKS,         // a well known service description
        PTR,         // a domain name pointer
        HINFO,       // host information
        MINFO,       // mailbox or mail list information
        MX,          // mail exchange
        TXT,         // text strings
    }

    impl AnswerTypes {
        pub fn len(&self) -> u16 {
            match self {
                AnswerTypes::A(_) => 4,
                v => unimplemented!("no implementation made for {:?}", v),
            }
        }
    }

    impl Write for AnswerTypes {
        fn write<'bout>(&self, buf: &'bout mut [u8]) -> &'bout mut [u8] {
            match self {
                AnswerTypes::A(payload) => {
                    let payload = payload.octets();
                    let (a, buf) = buf.split_at_mut(4);
                    a.clone_from_slice(&payload[..]);
                    buf
                }
                v => unimplemented!("no implementation made for {:?}", v),
            }
        }
    }

    #[derive(Debug, Clone, Copy, Eq, PartialEq, TryFromPrimitive)]
    #[repr(u16)]
    pub enum QueryTypes {
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

    impl<'f> Parse<'f> for QueryTypes {
        fn parse<'bin>(in_buf: &'bin [u8]) -> (&'bin [u8], Self)
        where
            'bin: 'f,
        {
            try_from_primitive(in_buf)
        }
    }

    impl Write for QueryTypes {
        fn write<'bout>(&self, buf: &'bout mut [u8]) -> &'bout mut [u8] {
            cast_helper_u16(*self as _, buf)
        }
    }

    #[derive(Debug, Clone, Copy, Eq, PartialEq, TryFromPrimitive)]
    #[repr(u16)]
    pub enum QueryClasses {
        IN = 1, //the Internet
        CS = 2, //the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
        CH = 3, //the CHAOS class
        HS = 4, //Hesiod [Dyer 87]
    }

    impl Write for QueryClasses {
        fn write<'bout>(&self, buf: &'bout mut [u8]) -> &'bout mut [u8] {
            cast_helper_u16(*self as _, buf)
        }
    }
    impl<'f> Parse<'f> for QueryClasses {
        fn parse<'bin>(in_buf: &'bin [u8]) -> (&'bin [u8], Self)
        where
            'bin: 'f,
        {
            try_from_primitive(in_buf)
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

    impl Write for DNSHeader<[u8; 12]> {
        fn write<'bout>(&self, buf: &'bout mut [u8]) -> &'bout mut [u8] {
            let (a, b) = buf.split_at_mut(12);
            a.copy_from_slice(&self.0);
            b
        }
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
        use crate::process;

        use super::*;

        const HEADER: [u8; 12] = [
            0x4b, 0x22, // ID
            0x1,  // 0 - QR = 0 | 1 - OPCODE = 0 | 5 AA = 0 | 6 TC = 0 | 7 RD = 1
            0x20, // 0 - RA = 0 | 1 Z = 2 | 4 RCODE = 0
            0x0, 0x1, // QDCOUNT
            0x0, 0x0, // ANCOUNT
            0x0, 0x1, // NSCOUNT
            0x1, 0x1, // ARCOUNT
        ];

        const DOMAIN_A: &str = "domain";
        const DOMAIN_B: &str = "com";

        #[test]
        fn test_dns_header() {
            let header = DNSHeader(&HEADER[..]);
            test_dns_fields(&header);
        }

        fn test_dns_fields(header: &DNSHeader<&[u8]>) {
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
            let mut h = [0; 12];
            let buf_len = test_lables_setup(&mut h);

            let (buf, lables) = Labels::parse(&h);
            assert_eq!(lables.words[0].word, DOMAIN_A);
            assert_eq!(lables.words[1].word, DOMAIN_B);
            assert_eq!(h.len() - buf.len(), buf_len);
        }

        fn test_lables_setup(mut buf: &mut [u8]) -> usize {
            buf[0] = DOMAIN_A.len() as _;
            buf[1..=DOMAIN_A.len()].copy_from_slice(DOMAIN_A.as_bytes());
            buf = &mut buf[1 + DOMAIN_A.len()..];

            buf[0] = DOMAIN_B.len() as _;
            buf[1..=DOMAIN_B.len()].copy_from_slice(DOMAIN_B.as_bytes());
            buf = &mut buf[1 + DOMAIN_B.len()..];
            buf[0] = 0;

            1 + DOMAIN_A.len() + 1 + DOMAIN_B.len() + 1
        }

        fn test_questions_setup(mut buf: &mut [u8]) -> usize {
            let offset = test_lables_setup(buf);
            buf = &mut buf[offset..];

            let (a, buf) = buf.split_at_mut(2);
            a.copy_from_slice(&(QueryTypes::MX as u16).to_be_bytes());

            let (a, _buf) = buf.split_at_mut(2);
            a.copy_from_slice(&(QueryClasses::CH as u16).to_be_bytes());

            offset + 2 + 2
        }

        #[test]
        fn test_questions() {
            let mut h = [0; 16];
            let buf_len = test_questions_setup(&mut h);

            let (buf, question) = Question::parse(&h);
            assert_eq!(question.labels.words[0].word, DOMAIN_A);
            assert_eq!(question.labels.words[1].word, DOMAIN_B);

            assert_eq!(question.qtype, QueryTypes::MX);
            assert_eq!(question.qclass, QueryClasses::CH);
            assert_eq!(h.len() - buf.len(), buf_len);
        }

        fn setup_query(buf: &mut [u8]) -> (&[u8], Request) {
            let mut offset = 12;
            buf[..offset].clone_from_slice(&HEADER[..]);
            offset += test_questions_setup(&mut buf[offset..]);
            Request::parse(&buf[..offset])
        }

        #[test]
        fn test_parse() {
            let mut buf = [0; 512];
            let (rest, req) = setup_query(&mut buf);
            assert_eq!(rest.len(), 0);

            test_dns_fields(&req.header);

            assert_eq!(req.questions[0].labels.words[0].word, DOMAIN_A);
            assert_eq!(req.questions[0].labels.words[1].word, DOMAIN_B);

            assert_eq!(req.questions[0].qtype, QueryTypes::MX);
            assert_eq!(req.questions[0].qclass, QueryClasses::CH);
        }

        fn test_dns_fields_v2(header: &DNSHeader<[u8; 12]>) {
            assert_eq!(0x4b22, header.packet_id());
            assert_eq!(true, header.query_reponse_indicator());
            assert_eq!(0, header.operation_code());
            assert_eq!(false, header.auth_answer());
            assert_eq!(false, header.truncation());
            assert_eq!(false, header.recursion_desired());
            assert_eq!(false, header.recursion_available());
            assert_eq!(0, header.reserved_z());
            assert_eq!(0, header.response_code());
            assert_eq!(1, header.question_count());
            assert_eq!(1, header.answer_record_count());
            assert_eq!(0, header.auth_record_count());
            assert_eq!(0, header.additional_record_count());
        }

        #[test]
        fn test_answer() {
            let res_buf = [
                0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, // domain
                0x03, 0x63, 0x6f, 0x6d, // com
                0x00, // NULL
                0x00, 0x01, // A
                0x00, 0x01, // IN
                0x00, 0x00, 0x00, 0x3c, // 60
                0x00, 0x04, // 4
                0x08, 0x08, 0x08, 0x08, // 8.8.8.8
            ];

            let answers = Answers {
                answers: vec![ResourceRecord {
                    name: Labels {
                        words: vec![
                            Label {
                                word: DOMAIN_A.into(),
                            },
                            Label {
                                word: DOMAIN_B.into(),
                            },
                        ],
                    },
                    atype: QueryTypes::A,
                    aclass: QueryClasses::IN,
                    ttl: 60,
                    len: 4,
                    answer: AnswerTypes::A(Ipv4Addr::new(8, 8, 8, 8)),
                }],
            };
            let mut buf = [0; 512];
            {
                let rest = answers.write(&mut buf[..]);
                assert_eq!(res_buf.len(), 512 - rest.len());
            }
            assert_eq!(&res_buf[..], &buf[..res_buf.len()]);
        }

        #[test]
        fn test_response() {
            let mut in_buf = [0; 512];
            let (_rest, req) = setup_query(&mut in_buf);

            let resp = process(req);

            test_dns_fields_v2(&resp.header);

            assert_eq!(resp.questions[0].labels.words[0].word, DOMAIN_A);
            assert_eq!(resp.questions[0].labels.words[1].word, DOMAIN_B);

            assert_eq!(resp.questions[0].qtype, QueryTypes::MX);
            assert_eq!(resp.questions[0].qclass, QueryClasses::CH);
        }
    }
}
