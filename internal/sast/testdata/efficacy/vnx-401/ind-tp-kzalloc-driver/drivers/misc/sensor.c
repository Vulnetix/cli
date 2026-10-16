#include <linux/module.h>
#include <linux/slab.h>
#include <linux/i2c.h>

struct sensor_priv {
    struct i2c_client *client;
    u8 regs[16];
};

static int sensor_read_id(struct i2c_client *client)
{
    return i2c_smbus_read_byte_data(client, 0x0f);
}

static int sensor_probe(struct i2c_client *client)
{
    struct sensor_priv *priv;
    int id;

    priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv)
        return -ENOMEM;

    id = sensor_read_id(client);
    if (id < 0) {
        dev_err(&client->dev, "failed to read chip id: %d\n", id);
~>        return id;
    }

    priv->client = client;
    i2c_set_clientdata(client, priv);
    return 0;
}
