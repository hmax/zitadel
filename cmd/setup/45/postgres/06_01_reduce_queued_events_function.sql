CREATE OR REPLACE FUNCTION subscriptions.reduce_queued_events()
RETURNS TRIGGER 
LANGUAGE PLpgSQL
AS $$
DECLARE
    "event" eventstore.events2;
BEGIN
    SELECT
        *
    INTO
        "event"
    FROM
        eventstore.events2 e
    WHERE
        e.instance_id = NEW.instance_id
        AND e.aggregate_type = NEW.aggregate_type
        AND e.aggregate_id = NEW.aggregate_id
        AND e."sequence" = NEW."sequence";

    EXECUTE 
        format('CALL %s($1)', NEW.reduce_function)
    USING
        "event";

    DELETE FROM 
        subscriptions.queue
    WHERE
        id = NEW.id;

    RETURN NEW;
END;
$$;
