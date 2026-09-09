use linfa::traits::{Fit};
use linfa_clustering::KMeans;
use ndarray::{array};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;

#[derive(Serialize, Deserialize, Debug)]
pub struct ModelConfig {
    pub centroids: Vec<Vec<f64>>,
    pub anomaly_cluster_index: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] Training K-Means Anomaly Detection Model...");

    // Features: [packet_rate, port_diversity, tcp_ratio, udp_ratio, icmp_ratio]
    // 1. Generate Synthetic Normal Baseline Data (low rate, low diversity)
    let normal_data = array![
        [2.0, 1.0, 1.0, 0.0, 0.0],
        [5.0, 1.0, 0.8, 0.2, 0.0],
        [1.0, 1.0, 0.0, 1.0, 0.0],
        [3.0, 2.0, 0.5, 0.5, 0.0],
        [4.0, 1.0, 0.9, 0.1, 0.0]
    ];

    // 2. Generate Synthetic Attack/Anomaly Data (high rate or high port diversity)
    let attack_data = array![
        [500.0, 1.0, 0.0, 1.0, 0.0],
        [1000.0, 1.0, 1.0, 0.0, 0.0],
        [800.0, 50.0, 0.5, 0.5, 0.0],
        [50.0, 30.0, 1.0, 0.0, 0.0],
        [1200.0, 2.0, 0.0, 0.0, 1.0]
    ];

    // Combine datasets into a Linfa Dataset
    let combined_data = ndarray::concatenate(
        ndarray::Axis(0),
        &[normal_data.view(), attack_data.view()],
    )?;
    let dataset = linfa::Dataset::from(combined_data);

    // Fit K-Means with k=2 clusters
    let model = KMeans::params(2)
        .max_n_iterations(100)
        .fit(&dataset)?;

    let centroids = model.centroids().to_owned();
    println!("[+] Trained Centroids:\n{:?}", centroids);

    // Identify which cluster represents the anomaly (higher avg packet_rate)
    let cluster_0_rate = centroids[[0, 0]];
    let cluster_1_rate = centroids[[1, 0]];
    let anomaly_cluster_index = if cluster_0_rate > cluster_1_rate { 0 } else { 1 };

    println!("[+] Anomaly Cluster Index identified as: {}", anomaly_cluster_index);

    // Convert ndarray centroids to std Vec for easy serialization
    let centroid_vecs: Vec<Vec<f64>> = centroids
        .outer_iter()
        .map(|row| row.to_vec())
        .collect();

    let config = ModelConfig {
        centroids: centroid_vecs,
        anomaly_cluster_index,
    };

    // Save model to model.json
    let json_data = serde_json::to_string_pretty(&config)?;
    let mut file = File::create("model.json")?;
    file.write_all(json_data.as_bytes())?;

    println!("[+] Model saved successfully to 'model.json'!");
    Ok(())
}
