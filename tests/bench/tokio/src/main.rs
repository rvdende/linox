#[tokio::main]
async fn main() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        tx.send(7).unwrap();
    });
    println!("tokio ok {}", rx.await.unwrap());
}
