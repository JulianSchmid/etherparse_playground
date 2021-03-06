use std::io::BufReader;
use std::fs::File;

extern crate csv;
extern crate clap;
use clap::{Arg, App};

#[derive(Debug, Default, Clone)]
struct Stats {
    average: Option<f64>,
    standard_deviation: Option<f64>,
    sum: f64,
    count: usize
}

impl Stats {

    fn from_slice(values: &[f64]) -> Stats {
        let sum = values.iter().sum::<f64>();
        let average: f64 = if values.len() > 0 {
            sum / (values.len() as f64)
        }  else {
            0.0
        };
        let sum2: f64 = values.iter().fold(0.0, |acc, x| (x - average)*(x - average) + acc);

        Stats {
            average: Some(average),
            standard_deviation: if values.len() > 1 {
                Some((sum2 / ((values.len() - 1) as f64)).sqrt())
            } else {
                None
            },
            sum: sum,
            count: values.len()
        }
    }
}

fn main() {

    let matches = App::new("generate statistics of a csv stats file generated by slice or decode")
                      .author("Julian Schmid")
                      .about("")
                          .arg(Arg::with_name("INPUT")
                               .help("input file")
                               .required(true)
                               .index(1))
                      .get_matches();

    //determine the count and maximum dimensionality
    let (dims, count) = {
        let mut rdr = csv::Reader::from_reader(BufReader::new(File::open(&matches.value_of("INPUT").unwrap()).unwrap()));
        let mut count: usize = 0;
        let mut dims: usize = 0;

        for record in rdr.records() {
            let len = record.unwrap().len();
            if len > dims {
                dims = len;
            }
            count += 1;
        }
        (dims, count)
    };

    //allocate the required memory
    let mut values = Vec::with_capacity(dims);
    for _i in 0..dims {
        values.push(Vec::with_capacity(count));
    }

    //collect values
    {
        let mut rdr = csv::Reader::from_reader(BufReader::new(File::open(&matches.value_of("INPUT").unwrap()).unwrap()));
        for record in rdr.records() {
            for (value, v) in record.unwrap().iter().zip(values.iter_mut()) {
                match value.parse::<f64>() {
                    Ok(value) => {
                        v.push(value);
                    },
                    Err(_) => {}
                }
            }
        }
    }

    //calculate the stats
    for ref dim_values in values {
        println!("{:?}", Stats::from_slice(&dim_values[..]));
    }
}