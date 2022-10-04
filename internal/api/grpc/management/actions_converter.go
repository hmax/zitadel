package management

import (
	action_grpc "github.com/zitadel/zitadel/internal/api/grpc/action"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/errors"
	"github.com/zitadel/zitadel/internal/eventstore/v1/models"
	"github.com/zitadel/zitadel/internal/query"
	mgmt_pb "github.com/zitadel/zitadel/pkg/grpc/management"
)

func CreateActionRequestToDomain(req *mgmt_pb.CreateActionRequest) *domain.Action {
	return &domain.Action{
		Name:          req.Name,
		Script:        req.Script,
		Timeout:       req.Timeout.AsDuration(),
		AllowedToFail: req.AllowedToFail,
	}
}

func updateActionRequestToDomain(req *mgmt_pb.UpdateActionRequest) *domain.Action {
	return &domain.Action{
		ObjectRoot: models.ObjectRoot{
			AggregateID: req.Id,
		},
		Name:          req.Name,
		Script:        req.Script,
		Timeout:       req.Timeout.AsDuration(),
		AllowedToFail: req.AllowedToFail,
	}
}

func listActionsToQuery(orgID string, req *mgmt_pb.ListActionsRequest) (_ *query.ActionSearchQueries, err error) {
	// set queries in same order as requested and append optional ownerRemoved
	queries := make([]query.SearchQuery, len(req.Queries)+2)
	queries[0], err = query.NewActionResourceOwnerQuery(orgID)
	if err != nil {
		return nil, err
	}
	for i, actionQuery := range req.Queries {
		queries[i+1], err = ActionQueryToQuery(actionQuery.Query)
		if err != nil {
			return nil, err
		}
	}

	if req.GetQuery().GetWithOwnerRemoved() {
		queries = append(queries)
	}
	return &query.ActionSearchQueries{
		SearchRequest: query.SearchRequest{
			Offset: req.Query.GetOffset(),
			Limit:  uint64(req.GetQuery().GetLimit()),
			Asc:    req.GetQuery().GetAsc(),
		},
		Queries: queries,
	}, nil
}

func ActionQueryToQuery(query interface{}) (query.SearchQuery, error) {
	switch q := query.(type) {
	case *mgmt_pb.ActionQuery_ActionNameQuery:
		return action_grpc.ActionNameQuery(q.ActionNameQuery)
	case *mgmt_pb.ActionQuery_ActionStateQuery:
		return action_grpc.ActionStateQuery(q.ActionStateQuery)
	case *mgmt_pb.ActionQuery_ActionIdQuery:
		return action_grpc.ActionIDQuery(q.ActionIdQuery)
	}
	return nil, errors.ThrowInvalidArgument(nil, "MGMT-dsg3z", "Errors.Query.InvalidRequest")
}
