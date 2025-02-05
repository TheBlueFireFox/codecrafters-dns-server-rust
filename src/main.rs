use sections::*;
use std::{
    net::{SocketAddr, UdpSocket},
    str::FromStr,
    usize,
};

const BUFFER_SIZE: usize = 512;
use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long, default_value = "8.8.8.8:53")]
    resolver: String,
}

fn main() {
    let args = Args::parse();
    let forward_socket_addr =
        SocketAddr::from_str(&args.resolver).expect("unable to parse socker address");

    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("0.0.0.0:2053").expect("Failed to bind to address");
    let mut buf = [0; BUFFER_SIZE];
    let mut response = [0; BUFFER_SIZE];
    let mut buffers = vec![vec![0; BUFFER_SIZE]; 20];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
            Ok((size, source)) => {
                let buf = &buf[..size];

                // println!();
                // println!("{:X?}", buf);
                let query = handle_recv(&buf, size, source);
                let qcount = query.header.question_count() as usize;

                let resp = process(
                    query,
                    &mut buffers[..qcount + 1],
                    &udp_socket,
                    &forward_socket_addr,
                );

                let len = handle_send(&mut response, &resp);
                let res = &response[..len];
                // println!("{:X?}", res);

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

fn process<'req, 'bufs>(
    req: Request<'req>,
    mut buffers: &'bufs mut [Vec<u8>],
    socket: &UdpSocket,
    addr: &SocketAddr,
) -> Response<'req, 'bufs>
where
    'req: 'bufs,
{
    let mut answers = vec![];

    for question in &req.questions {
        let (in_buf, res_buf) = buffers.split_at_mut(1);
        buffers = res_buf;
        let in_buf = &mut in_buf[0][..];

        // these clones are cheap as both structs are simple references
        let mut header: [u8; 12] = req.header.clone().into();

        {
            let mut header = DNSHeader(&mut header[..]);
            // choose a random id for fun and to make sure we are getting the currect id back
            header.set_packet_id(rand::random());
            // we only ever send a single question
            header.set_question_count(1);
        }

        let creq = Request {
            header: DNSHeader(&header[..]),
            questions: vec![question.clone()],
        };
        let bbuf_len = creq.write(in_buf).len();

        let size = send_request_forward(socket, addr, &mut in_buf[..], bbuf_len);

        let (_, response) = Response::parse(&in_buf[..size]);

        if let Some(aw) = response.answers.answers.get(0) {
            let rr = ResourceRecord {
                name: aw.name.clone(),
                atype: aw.atype,
                aclass: aw.aclass,
                ttl: aw.ttl,
                len: aw.len,
                answer: aw.answer.clone(),
            };

            answers.push(rr);
        }
    }

    let header = handle_response_header(&req.header, answers.len());

    let answers = Answers { answers };

    Response {
        header,
        questions: req.questions,
        answers,
    }
}

fn send_request_forward(
    socket: &UdpSocket,
    addr: &SocketAddr,
    in_buf: &mut [u8],
    packet_size: usize,
) -> usize {
    // this process assumes that the only request arriving at the server
    // the the one, we previously send out
    let size = socket
        .send_to(&in_buf[..packet_size], addr)
        .expect("unable to send to forwading server");
    assert_eq!(size, packet_size, "incorrect packet size");

    let (size, from) = socket
        .recv_from(in_buf)
        .expect("unable to send to forwading server");

    assert_eq!(from, *addr, "got packed from unexpected socket addres");

    size
}

fn handle_send(res_buf: &mut [u8], res: &Response<'_, '_>) -> usize {
    let len = res_buf.len();
    let buf = res.write(res_buf);
    len - buf.len()
}

fn handle_response_header<'a>(header: &DNSHeader<&[u8]>, anwsers: usize) -> DNSHeader<[u8; 12]> {
    let mut new_header = DNSHeader([0; 12]);
    new_header.set_packet_id(header.packet_id());
    new_header.set_query_reponse_indicator(true);
    new_header.set_operation_code(header.operation_code());
    new_header.set_auth_answer(false);
    new_header.set_truncation(false);
    new_header.set_recursion_desired(header.recursion_desired());
    new_header.set_recursion_available(header.recursion_desired());
    new_header.set_reserved_z(0);
    let ropcode = if header.operation_code() == 0 {
        0
    } else {
        4 // error not implemented
    };
    new_header.set_response_code(ropcode);
    new_header.set_question_count(header.question_count());
    new_header.set_answer_record_count(anwsers as _);
    new_header.set_auth_record_count(0);
    new_header.set_additional_record_count(0);

    new_header
}

mod sections {
    use std::{collections::HashMap, net::Ipv4Addr};

    use num_enum::TryFromPrimitive;

    use crate::BUFFER_SIZE;

    #[derive(Debug)]
    pub struct Request<'in_buffer> {
        pub header: DNSHeader<&'in_buffer [u8]>,
        pub questions: Vec<Question<'in_buffer>>,
    }

    impl<'buffer> Request<'buffer> {
        pub fn parse<'bin>(in_buf: &'bin [u8]) -> (usize, Self)
        where
            'bin: 'buffer,
        {
            let (_, header) = DNSHeader::parse(in_buf);

            let mut offset = 12;
            let mut questions = vec![];
            for _ in 0..header.question_count() {
                let (buf, question) = Question::parse(in_buf, offset);
                offset = in_buf.len() - buf.len();
                questions.push(question);
            }
            (offset, Self { header, questions })
        }

        pub fn write<'bout>(&'buffer self, mut buf: &'bout mut [u8]) -> &'bout mut [u8]
        where
            'bout: 'buffer,
            'buffer: 'bout,
        {
            buf = self.header.write(buf);

            let mut map = HashMap::new();

            for question in &self.questions {
                let (imap, ibuf) = question.write(buf, map);
                map = imap;
                buf = ibuf;
            }

            buf
        }
    }

    #[derive(Debug, Clone)]
    pub struct Question<'in_buf> {
        pub labels: Labels<'in_buf>,
        pub qtype: QueryTypes,
        pub qclass: QueryClasses,
    }

    impl<'f> Question<'f> {
        pub fn parse<'bin>(buf: &'bin [u8], offset: usize) -> (&'bin [u8], Self)
        where
            'bin: 'f,
        {
            let (offset, labels) = Labels::parse(buf, offset);
            let (buf, qtype) = QueryTypes::parse(&buf[offset..]);
            let (buf, qclass) = QueryClasses::parse(buf);

            (
                buf,
                Question {
                    labels,
                    qtype,
                    qclass,
                },
            )
        }

        pub fn write<'bout>(
            &'f self,
            mut buf: &'bout mut [u8],
            mut map: HashMap<&'f [Label<'bout>], usize>,
        ) -> (HashMap<&'f [Label<'bout>], usize>, &'bout mut [u8])
        where
            'bout: 'f,
            'f: 'bout,
        {
            let (imap, ibuf) = self.labels.write(buf, map);
            map = imap;
            buf = ibuf;
            buf = self.qtype.write(buf);
            buf = self.qclass.write(buf);

            (map, buf)
        }
    }

    #[derive(Debug)]
    pub struct Response<'in_buffer, 'answers> {
        pub header: DNSHeader<[u8; 12]>,
        pub questions: Vec<Question<'in_buffer>>,
        pub answers: Answers<'answers>,
    }

    impl<'buffer, 'answers> Response<'buffer, 'answers> {
        pub fn parse<'bin>(in_buf: &'bin [u8]) -> (usize, Self)
        where
            'bin: 'buffer,
            'bin: 'answers,
        {
            let (_, header) = DNSHeader::parse(in_buf);

            let mut offset = 12;
            let mut questions = vec![];
            for _ in 0..header.question_count() {
                let (buf, question) = Question::parse(in_buf, offset);
                offset = in_buf.len() - buf.len();
                questions.push(question);
            }

            let (_, answers) = Answers::parse(in_buf, offset, header.answer_record_count() as _);

            (
                offset,
                Self {
                    header: DNSHeader(header.into()),
                    questions,
                    answers,
                },
            )
        }
        pub fn write<'bout>(&'buffer self, mut buf: &'bout mut [u8]) -> &'bout mut [u8]
        where
            'bout: 'buffer,
            'buffer: 'bout,
        {
            buf = self.header.write(buf);

            let mut map = HashMap::new();

            for question in &self.questions {
                let (imap, ibuf) = question.write(buf, map);
                map = imap;
                buf = ibuf;
            }

            let (_, buf) = self.answers.write(buf, map);

            buf
        }
    }

    #[derive(Debug)]
    pub struct Answers<'in_buf> {
        pub answers: Vec<ResourceRecord<'in_buf>>,
    }

    impl<'ans> Answers<'ans> {
        pub fn write<'bout>(
            &'ans self,
            mut buf: &'bout mut [u8],
            mut map: HashMap<&'ans [Label<'bout>], usize>,
        ) -> (HashMap<&'ans [Label<'bout>], usize>, &'bout mut [u8])
        where
            'bout: 'ans,
            'ans: 'bout,
        {
            for answer in &self.answers {
                let (imap, ibuf) = answer.write(buf, map);
                map = imap;
                buf = ibuf;
            }
            (map, buf)
        }

        pub fn parse<'bin>(
            buf: &'bin [u8],
            mut offset: usize,
            answer_count: usize,
        ) -> (&'bin [u8], Self)
        where
            'bin: 'ans,
        {
            let mut answers = vec![];

            for _ in 0..answer_count {
                let (ibuf, answer) = ResourceRecord::parse(buf, offset);
                offset = buf.len() - ibuf.len();
                answers.push(answer);
            }

            (buf, Self { answers })
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

    impl<'f> ResourceRecord<'f> {
        pub fn write<'m, 'bout>(
            &'f self,
            mut buf: &'bout mut [u8],
            mut map: HashMap<&'f [Label<'bout>], usize>,
        ) -> (HashMap<&'f [Label<'bout>], usize>, &'bout mut [u8])
        where
            'bout: 'f,
            'f: 'bout,
        {
            (map, buf) = self.name.write(buf, map);
            buf = self.atype.write(buf);
            buf = self.aclass.write(buf);
            buf = cast_helper_u32(self.ttl, buf);
            buf = cast_helper_u16(self.len, buf);
            buf = self.answer.write(buf);

            (map, buf)
        }

        pub fn parse<'bin>(buf: &'bin [u8], offset: usize) -> (&'bin [u8], Self)
        where
            'bin: 'f,
        {
            let (offset, name) = Labels::parse(buf, offset);
            let (buf, at) = QueryTypes::parse(&buf[offset..]);
            let (buf, ac) = QueryClasses::parse(buf);
            let (buf, ttl) = parse_u32(buf);
            let (buf, len) = parse_u16(buf);
            let (buf, answer) = AnswerTypes::parse(buf, at, len as _);

            (
                buf,
                ResourceRecord {
                    name,
                    atype: at,
                    aclass: ac,
                    ttl,
                    len,
                    answer,
                },
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Labels<'ibuf> {
        pub words: Vec<Label<'ibuf>>,
    }

    impl<'f> Labels<'f> {
        pub fn parse<'bin>(buf: &'bin [u8], offset: usize) -> (usize, Self)
        where
            'bin: 'f,
        {
            Self::parse_helper(buf, offset, 1)
        }

        fn parse_helper<'bin>(buf: &'bin [u8], mut offset: usize, rec_count: usize) -> (usize, Self)
        where
            'bin: 'f,
        {
            let mut words = Vec::new();
            loop {
                match buf.get(offset) {
                    None => panic!(
                        "something when wrong, \
                         while processing the buffer \
                         should not be empty already."
                    ),
                    Some(0x0) => {
                        // end condition
                        return (offset + 1, Self { words });
                    }
                    Some(&v) if (v & 0b1100_0000) > 0 => {
                        // end condition
                        if rec_count == 0 {
                            return (offset + 2, Self { words });
                        }

                        let v = v as usize;
                        let v2 = buf[offset + 1] as usize;
                        let label_offset = ((v & 0b0011_1111) << 8) | v2;

                        // using 0 as to not recurse again
                        let (_, mut decompressed) = Labels::parse_helper(buf, label_offset, 0);
                        words.append(&mut decompressed.words);

                        return (offset + 2, Self { words });
                    }
                    Some(_) => {
                        let word = Label::parse_uncompressed(buf, offset);
                        offset += word.len() + 1;
                        words.push(word);
                    }
                }
            }
        }

        pub fn write<'bout>(
            &'f self,
            mut buf: &'bout mut [u8],
            mut map: HashMap<&'f [Label<'bout>], usize>,
        ) -> (HashMap<&'f [Label<'bout>], usize>, &'bout mut [u8])
        where
            'bout: 'f,
            'f: 'bout,
        {
            for (i, lable) in self.words.iter().enumerate() {
                // differentiate if rest of self.words already exists in map
                match map.get(&self.words[i..]) {
                    Some(&v) => {
                        //
                        buf[0] = 0b1100_0000;
                        buf[1] = v as _;
                        return (map, &mut buf[2..]);
                    }
                    None => {
                        // we need to continue to iterate
                        let offset = BUFFER_SIZE - buf.len();
                        map.insert(&self.words[i..], offset);
                        buf = lable.write(buf);
                    }
                }
            }

            buf[0] = 0;

            (map, &mut buf[1..])
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct Label<'ibuf> {
        pub word: &'ibuf str,
    }

    impl<'f> Label<'f> {
        pub fn write<'bout>(&self, buf: &'bout mut [u8]) -> &'bout mut [u8] {
            let (a, buf) = buf.split_at_mut(1);
            a[0] = self.word.len() as _;

            let (a, buf) = buf.split_at_mut(self.word.len());
            a.copy_from_slice(self.word.as_bytes());

            buf
        }

        pub fn len(&self) -> usize {
            self.word.len()
        }

        pub fn parse_uncompressed<'bin>(buf: &'bin [u8], offset: usize) -> Self
        where
            'bin: 'f,
        {
            let len = buf[offset] as _;
            let word = &buf[offset + 1..][..len];
            let word = std::str::from_utf8(word).expect("unable to convert domain into utf8");
            Label { word }
        }
    }

    fn try_from_primitive<T>(buf: &[u8]) -> (&[u8], T)
    where
        T: TryFromPrimitive<Primitive = u16>,
        <T as TryFromPrimitive>::Error: std::fmt::Debug,
    {
        let (buf, v) = parse_u16(buf);

        let res = T::try_from_primitive(v).expect("unable to convert to the given type");

        (buf, res)
    }

    fn parse_u16(buf: &[u8]) -> (&[u8], u16) {
        let (v, buf) = buf.split_at(2);
        let res = v.try_into().expect("unable to convert");
        (buf, u16::from_be_bytes(res))
    }

    fn parse_u32(buf: &[u8]) -> (&[u8], u32) {
        let (v, buf) = buf.split_at(4);
        let res = v.try_into().expect("unable to convert");
        (buf, u32::from_be_bytes(res))
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
        pub fn write<'bout>(&self, buf: &'bout mut [u8]) -> &'bout mut [u8] {
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

        pub fn parse(buf: &[u8], qt: QueryTypes, len: usize) -> (&[u8], Self) {
            match qt {
                QueryTypes::A => {
                    assert_eq!(4, len);
                    let (c, buf) = buf.split_at(len);

                    (buf, AnswerTypes::A(Ipv4Addr::new(c[0], c[1], c[2], c[3])))
                }
                QueryTypes::NS => unimplemented!(),
                QueryTypes::MD => unimplemented!(),
                QueryTypes::MF => unimplemented!(),
                QueryTypes::CNAME => unimplemented!(),
                QueryTypes::SOA => unimplemented!(),
                QueryTypes::MB => unimplemented!(),
                QueryTypes::MG => unimplemented!(),
                QueryTypes::MR => unimplemented!(),
                QueryTypes::NULL => unimplemented!(),
                QueryTypes::WKS => unimplemented!(),
                QueryTypes::PTR => unimplemented!(),
                QueryTypes::HINFO => unimplemented!(),
                QueryTypes::MINFO => unimplemented!(),
                QueryTypes::MX => unimplemented!(),
                QueryTypes::TXT => unimplemented!(),
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

    impl QueryTypes {
        pub fn parse<'bin>(in_buf: &'bin [u8]) -> (&'bin [u8], Self) {
            try_from_primitive(in_buf)
        }

        pub fn write<'bout>(&self, buf: &'bout mut [u8]) -> &'bout mut [u8] {
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

    impl QueryClasses {
        pub fn write<'bout>(&self, buf: &'bout mut [u8]) -> &'bout mut [u8] {
            cast_helper_u16(*self as _, buf)
        }
        pub fn parse(in_buf: &[u8]) -> (&[u8], Self) {
            try_from_primitive(in_buf)
        }
    }

    bitfield::bitfield! {
        #[derive(Clone)]
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

    impl DNSHeader<[u8; 12]> {
        pub fn write<'bout>(&self, buf: &'bout mut [u8]) -> &'bout mut [u8] {
            DNSHeader(&self.0[..]).write(buf)
        }
    }

    impl<'f> DNSHeader<&'f [u8]> {
        pub fn parse<'bin>(in_buf: &'bin [u8]) -> (&'bin [u8], Self)
        where
            'bin: 'f,
        {
            let (a, b) = in_buf.split_at(12);

            (b, Self(a))
        }

        pub fn write<'bout>(&self, buf: &'bout mut [u8]) -> &'bout mut [u8] {
            let (a, b) = buf.split_at_mut(12);
            a.copy_from_slice(&self.0);
            b
        }
    }
    impl<'f> From<DNSHeader<&'f [u8]>> for [u8; 12] {
        fn from(value: DNSHeader<&'f [u8]>) -> Self {
            let mut buf = [0; 12];
            buf[..].clone_from_slice(&value.0[..]);
            buf
        }
    }

    #[cfg(test)]
    mod test {
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
        fn test_labels() {
            let mut h = [0; 12];
            let buf_len = test_labels_setup(&mut h);

            let (offset, lables) = Labels::parse(&h, 0);
            assert_eq!(lables.words[0].word, DOMAIN_A);
            assert_eq!(lables.words[1].word, DOMAIN_B);
            assert_eq!(offset, buf_len);
        }

        fn test_labels_setup(mut buf: &mut [u8]) -> usize {
            buf[0] = DOMAIN_A.len() as _;
            buf[1..=DOMAIN_A.len()].copy_from_slice(DOMAIN_A.as_bytes());
            buf = &mut buf[1 + DOMAIN_A.len()..];

            buf[0] = DOMAIN_B.len() as _;
            buf[1..=DOMAIN_B.len()].copy_from_slice(DOMAIN_B.as_bytes());
            buf = &mut buf[1 + DOMAIN_B.len()..];
            buf[0] = 0;

            1 + DOMAIN_A.len() + 1 + DOMAIN_B.len() + 1
        }

        fn test_compressed_labels_setup(mut buf: &mut [u8]) -> usize {
            buf[0] = DOMAIN_A.len() as _;
            buf[1..=DOMAIN_A.len()].copy_from_slice(DOMAIN_A.as_bytes());
            buf = &mut buf[1 + DOMAIN_A.len()..];

            buf[0] = DOMAIN_B.len() as _;
            buf[1..=DOMAIN_B.len()].copy_from_slice(DOMAIN_B.as_bytes());
            buf = &mut buf[1 + DOMAIN_B.len()..];

            buf[0] = 0b1100_0000;
            buf[1] = 1 + DOMAIN_A.len() as u8; // DOMAIN_B

            1 + DOMAIN_A.len() + 1 + DOMAIN_B.len() + 1 + 1
        }

        #[test]
        fn test_compressed_labels() {
            let mut h = [0; 13];
            let buf_len = test_compressed_labels_setup(&mut h);

            let (offset, lables) = Labels::parse(&h, 0);
            assert_eq!(lables.words[0].word, DOMAIN_A);
            assert_eq!(lables.words[1].word, DOMAIN_B);
            assert_eq!(lables.words[2].word, DOMAIN_B);
            assert_eq!(offset, buf_len);
        }

        fn test_questions_setup(mut buf: &mut [u8]) -> usize {
            let offset = test_labels_setup(buf);
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

            let (buf, question) = Question::parse(&h, 0);
            assert_eq!(question.labels.words[0].word, DOMAIN_A);
            assert_eq!(question.labels.words[1].word, DOMAIN_B);

            assert_eq!(question.qtype, QueryTypes::MX);
            assert_eq!(question.qclass, QueryClasses::CH);
            assert_eq!(h.len() - buf.len(), buf_len);
        }

        fn test_questions_compressed_setup(mut buf: &mut [u8]) -> usize {
            let mut offset = test_labels_setup(buf);
            buf = &mut buf[offset..];

            buf = cast_helper_u16(QueryTypes::MX as u16, buf);
            buf = cast_helper_u16(QueryClasses::CH as u16, buf);
            offset += 4;

            buf[0] = 0b1100_0000;
            buf[1] = 1 + DOMAIN_A.len() as u8;
            buf = &mut buf[2..];
            offset += 2;

            buf = cast_helper_u16(QueryTypes::MX as u16, buf);
            let _ = cast_helper_u16(QueryClasses::CH as u16, buf);
            offset += 4;
            offset
        }

        #[test]
        fn test_questions_compressed() {
            let mut h = [0; 512];
            let _buf_len = test_questions_compressed_setup(&mut h);

            let mut offset = 0;
            // domain.com
            let (qbuf, question) = Question::parse(&h, offset);
            offset += h.len() - qbuf.len();
            println!("{offset}");

            assert_eq!(question.labels.words[0].word, DOMAIN_A);
            assert_eq!(question.labels.words[1].word, DOMAIN_B);

            assert_eq!(question.qtype, QueryTypes::MX);
            assert_eq!(question.qclass, QueryClasses::CH);

            // com
            let (qbuf, question) = Question::parse(&h, offset);
            offset += h.len() - qbuf.len();
            println!("{offset}");

            assert_eq!(question.labels.words[0].word, DOMAIN_B);

            assert_eq!(question.qtype, QueryTypes::MX);
            assert_eq!(question.qclass, QueryClasses::CH);
        }

        fn setup_query(buf: &mut [u8]) -> (usize, Request) {
            let mut offset = 12;
            buf[..offset].clone_from_slice(&HEADER[..]);
            offset += test_questions_setup(&mut buf[offset..]);
            Request::parse(&buf[..offset])
        }

        #[test]
        fn test_request() {
            let mut buf = [0; 512];
            let (_rest, req) = setup_query(&mut buf);

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
            assert_eq!(true, header.recursion_desired());
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
                let map = HashMap::new();
                let (map, rest) = answers.write(&mut buf[..], map);
                assert_eq!(map.len(), 2);
                assert_eq!(res_buf.len(), 512 - rest.len());
            }
            assert_eq!(&res_buf[..], &buf[..res_buf.len()]);
        }

        // #[test]
        // fn test_response() {
        //     let mut in_buf = [0; 512];
        //     let (_rest, req) = setup_query(&mut in_buf);

        //     let resp = process(req);

        //     test_dns_fields_v2(&resp.header);

        //     assert_eq!(resp.questions[0].labels.words[0].word, DOMAIN_A);
        //     assert_eq!(resp.questions[0].labels.words[1].word, DOMAIN_B);

        //     assert_eq!(resp.questions[0].qtype, QueryTypes::MX);
        //     assert_eq!(resp.questions[0].qclass, QueryClasses::CH);
        // }

        #[test]
        fn test_compression() {
            let arr = [
                88, 103, // Packet ID
                1, 0, // CONFIGURATION
                0, 2, // Question Count
                0, 0, // AnCount
                0, 0, // NSCOUNT
                0, 0, // ARCOUNT
                3, 97, 98, 99, // abc
                17, 108, 111, 110, 103, 97, 115, 115, 100, 111, 109, 97, 105, 110, 110, 97, 109,
                101, // longassdomainname
                3, 99, 111, 109, // com
                0,   // NULL
                0, 1, // A
                0, 1, // IN
                3, 100, 101, 102, // def
                192, 16, // pointer to longassdomainname.com
                0, 1, // A
                0, 1, // IN
            ];

            let (_, req) = Request::parse(&arr);
            assert_eq!(req.header.question_count(), 2);
            assert_eq!("abc", req.questions[0].labels.words[0].word);
            assert_eq!("longassdomainname", req.questions[0].labels.words[1].word);
            assert_eq!("com", req.questions[0].labels.words[2].word);
            assert_eq!(QueryTypes::A, req.questions[0].qtype);
            assert_eq!(QueryClasses::IN, req.questions[0].qclass);

            assert_eq!("def", req.questions[1].labels.words[0].word);
            assert_eq!("longassdomainname", req.questions[1].labels.words[1].word);
            assert_eq!("com", req.questions[1].labels.words[2].word);
            assert_eq!(QueryTypes::A, req.questions[1].qtype);
            assert_eq!(QueryClasses::IN, req.questions[1].qclass);
        }

        // #[test]
        // fn test_response_compression() {
        //     let mut in_buf = [0; BUFFER_SIZE];
        //     let mut buf = [0; BUFFER_SIZE];
        //     let (_rest, req) = setup_query(&mut in_buf);

        //     let resp = process(req);
        //     resp.write(&mut buf);

        //     #[rustfmt::skip]
        //     let exp = [
        //         0x4b, 0x22, // packet id
        //         129, 0,     // configuration
        //         0, 1,       // question count
        //         0, 1,       // answer count
        //         0, 0,       // ..
        //         0, 0,       // ..
        //         6, 100, 111, 109, 97, 105, 110, // domain
        //         3, 99, 111, 109, // com
        //         0,           // null
        //         0,  15,      // mx
        //         0, 3,        // ch
        //         192, 12,     // offset 12 => domain.com
        //         0, 15,       // mx
        //         0, 3,        // ch
        //         0, 0, 0, 60, // ttl
        //         0, 4,        // len
        //         8, 8, 8, 8   // payload
        //     ];

        //     assert_eq!(&exp[..], &buf[..exp.len()]);
        // }

        #[test]
        fn test_response_forward() {
            #[rustfmt::skip]
            let arr = [
                62, 186,        // packet id
                129, 128,       // configuration
                0, 1,           // question count
                0, 1,           // answer count
                0, 0,           // ..
                0, 0,           // ..
                12, 99, 111, 100, 101, 99, 114, 97, 102, 116, 101, 114, 115, // codecrafters
                2, 105, 111,    // io
                0,              // NULL
                0, 1,           // A
                0, 1,           // IN
                192, 12,        // offset 12 => codecrafters.io
                0, 1,           // A
                0, 1,           // IN
                0, 0, 11, 148,  // ttl
                0, 4,           // len
                76, 76, 21, 21  // payload
            ];
            let (_, response) = Response::parse(&arr);

            assert_eq!(
                AnswerTypes::A(Ipv4Addr::new(76, 76, 21, 21)),
                response.answers.answers[0].answer
            );

            assert_eq!(2964, response.answers.answers[0].ttl);
        }
    }
}
