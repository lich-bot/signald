ALTER TABLE signald_message_queue DROP COLUMN legacy_message;
ALTER TABLE signald_message_queue ADD COLUMN urgent BOOL DEFAULT FALSE;
ALTER TABLE signald_message_queue ADD COLUMN updated_pni TEXT;
ALTER TABLE signald_message_queue ADD COLUMN story BOOL DEFAULT FALSE;

-- per change in https://github.com/signalapp/Signal-Android/commit/c4bef8099f23481162f9039867325fc62dd6a8b6
-- converted with python:
-- >>> from base64 import b64decode
-- >>> b64decode(input("base64: ")).hex()
UPDATE servers SET
    zk_group_public_params = E'\\00c85fe72c15c084d932c7dffde0b2b9d671f490e692491b57a3c89f31b8a7cc7756a54948588cbe7be510a5ae4686ffd5e6887ad477d4861e01b9b435d3ae1c7f108be45ec62d702e5a73228d60b2d1d605f673cb5faa1d15790384ea3e9d7963304f9b45928205ba3db4a7f85e257f9ed50a71c5ee9f12bf3000d996493d825446df17edb6e0f87de2f8f1231fd0d722d344aacdac35cba0dfbc594032e6ed7dfa9cea063ece785ec106ccf74457e8ad40d1941448d8e97f54bfe01cba4b3b369c86bc2a0ac46c202a01395f227e9cd2a5c871ce2dbe8dd4db87c81ad9ae0b58fc96091d1a28a39084a98281a9d16799b4d5184902bc92b12e78f02967fe7c43e859e4058f939b0e370a3197f6266d807baf71fa2914e60057b119a817de065d32df374fef2edf7c2833e7c700102fd8f95758c6398f23425e8c2f112ce7a7305cdd1da829c89b3547dd3653d5c27c496d41457eaa215c44ce3b121b1df2c45decb808a53cca86469e1f7f2a298cc0f525788a4764702cace2cd47b97bc5f218ecbd7e9973870de35734d1c9465345264a90c2d6710fe0bf413868e34daace0f'
    WHERE server_uuid = '6e2eb5a8-5706-45d0-8377-127a816411a4';

UPDATE servers SET
    zk_group_public_params = E'\\001498db555c91071b49754d08645825c7d61e200c666a53b5310b7039b181d15bb69fdb5ac4b165d30acdf0a9f2bbc8b3ca1c094dc1dfb7d3debe0c8b9a807a6786791d97fbf626386479a1fba2eed0f998341fb2d008f62fb85a932d21ef0a0b7c14e70dc89eadee356566a06b692a776c35fc09ac28341ddf7398e6e1ca95274a47d89f6a2830e3a70697dd6a746daef7ad6546b20cc482e624917172a9765ba4ae9cf3b0222f1308f042525854f3903e3e15d05e145d705d1d22cad39ba83c10901bc1bdad820679d62c0a52579dbae01981b778c4c6e619f1e17e27b404418042ee3165941047d22b49a35e0fbfda53e659c4d9591f6792a81040fd2d6f3ba23e6ef81f6c0c3b8bb559a7def94c32225213f4beca2d2d7d030f2be2c3eb5d'
    WHERE server_uuid = '97c17f0c-e53b-426f-8ffa-c052d4183f83';
